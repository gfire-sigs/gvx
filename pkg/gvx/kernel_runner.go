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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/devices/memdev"
	"z.gfire.dev/gvx/pkg/sentry/devices/ttydev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/dev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/devpts"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/erofs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/overlay"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/proc"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/loader"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/strace"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"

	// Register Linux syscall tables and socket families in the Sentry kernel.
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink/route"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/unix"
	_ "z.gfire.dev/gvx/pkg/sentry/syscalls/linux"
)

func init() {
	logDest := io.Writer(os.Stderr)
	if os.Getenv("GVX_DEBUG_LOG") == "" && os.Getenv("GVX_STRACE") == "" {
		logDest = io.Discard
	}
	log.SetTarget(&log.Writer{Next: engineFaultLog{next: logDest}})
	if os.Getenv("GVX_DEBUG_LOG") == "2" {
		log.SetLevel(log.Debug)
	}
	if os.Getenv("GVX_STRACE") != "" {
		strace.Initialize()
		strace.EnableAll(strace.SinkTypeLog)
	}
	cpuid.Initialize()
	_ = usage.Init()
	if usage.MemoryAccounting == nil {
		usage.MemoryAccounting = &usage.MemoryLocked{
			RTMemoryStats: &usage.RTMemoryStats{},
		}
	}
}

// errRunConsumed reports a second Run call. The first Run consumes the kernel
// MemoryFile, and the host lockdown denies the creation of a new one.
var errRunConsumed = errors.New("gvx: Sandbox.Run already ran and consumed the kernel memory file")

type ttyState struct {
	mu         sync.Mutex
	termios    linux.KernelTermios
	winsize    linux.Winsize
	fgPgrp     int32
	session    int32
	rawHost    bool
	lineBuf    []byte
	readBuf    []byte
	pendingEOF bool
	hostEOF    bool
	hostErr    error
	stopped    bool

	in    io.Reader
	out   io.Writer
	outMu *sync.Mutex
	ktty  *kernel.TTY
	wq    waiter.Queue
}

var _ kernel.TTYOperations = (*ttyState)(nil)

func newDefaultTTYState() *ttyState {
	return newTTYState(nil, nil, false, 24, 80)
}

func newTTYState(in io.Reader, out io.Writer, rawHost bool, rows, cols uint16) *ttyState {
	if rows == 0 {
		rows = 24
	}
	if cols == 0 {
		cols = 80
	}
	t := &ttyState{
		termios: linux.DefaultReplicaTermios,
		winsize: linux.Winsize{
			Row: rows,
			Col: cols,
		},
		fgPgrp:  1,
		session: 1,
		rawHost: rawHost,
		in:      in,
		out:     out,
		outMu:   new(sync.Mutex),
	}
	t.ktty = kernel.NewTTY(0, t)
	return t
}

func (t *ttyState) IncRef()                  {}
func (t *ttyState) DecRef(gvcontext.Context) {}

func (t *ttyState) OpenTTY(ctx gvcontext.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &stdioFD{
		reader: t.in,
		writer: t.out,
		tty:    t,
		mu:     t.outMu,
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		SpecialFile: true,
	}); err != nil {
		return nil, err
	}
	if opts.Flags&linux.O_NOCTTY == 0 {
		if tsk := kernel.TaskFromContext(ctx); tsk != nil && t.ktty != nil {
			_ = tsk.ThreadGroup().SetControllingTTY(ctx, t.ktty, false, fd.vfsfd.IsReadable())
		}
	}
	return &fd.vfsfd, nil
}

func (t *ttyState) startPump() {
	if t.in == nil {
		t.finishInput(io.EOF)
		return
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := t.in.Read(buf)
			if n > 0 {
				if !t.consumeInput(buf[:n]) {
					return
				}
			}
			if err != nil {
				t.finishInput(err)
				return
			}
		}
	}()
}

func (t *ttyState) stop() {
	t.mu.Lock()
	t.stopped = true
	t.hostEOF = true
	t.mu.Unlock()
	if d, ok := t.in.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now())
	}
	t.wq.Notify(waiter.ReadableEvents | waiter.EventHUp)
}

func (t *ttyState) finishInput(err error) {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	if len(t.lineBuf) > 0 {
		t.readBuf = append(t.readBuf, t.lineBuf...)
		t.lineBuf = t.lineBuf[:0]
	}
	t.hostEOF = true
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.hostErr = err
	}
	t.mu.Unlock()
	t.wq.Notify(waiter.ReadableEvents | waiter.EventHUp)
}

func (t *ttyState) cc(idx int) byte {
	if idx < 0 || idx >= len(t.termios.ControlCharacters) {
		return 0
	}
	return t.termios.ControlCharacters[idx]
}

func (t *ttyState) appendOutputNewlineLocked(dst *[]byte) {
	if t.termios.OEnabled(linux.OPOST) && t.termios.OEnabled(linux.ONLCR) {
		*dst = append(*dst, '\r', '\n')
		return
	}
	*dst = append(*dst, '\n')
}

func (t *ttyState) appendEchoByteLocked(dst *[]byte, b byte) {
	if b == '\n' {
		t.appendOutputNewlineLocked(dst)
		return
	}
	if (b < 0x20 || b == 0x7f) && b != '\t' && t.termios.LEnabled(linux.ECHOCTL) {
		if b == 0x7f {
			*dst = append(*dst, '^', '?')
		} else {
			*dst = append(*dst, '^', b+0x40)
		}
		return
	}
	*dst = append(*dst, b)
}

func (t *ttyState) popLastCharLocked() (erased byte, ok bool) {
	if len(t.lineBuf) == 0 {
		return 0, false
	}
	if t.termios.IEnabled(linux.IUTF8) {
		_, size := utf8.DecodeLastRune(t.lineBuf)
		if size > 0 {
			b := t.lineBuf[len(t.lineBuf)-size]
			t.lineBuf = t.lineBuf[:len(t.lineBuf)-size]
			return b, true
		}
	}
	b := t.lineBuf[len(t.lineBuf)-1]
	t.lineBuf = t.lineBuf[:len(t.lineBuf)-1]
	return b, true
}

func (t *ttyState) echoEraseCharLocked(dst *[]byte, erased byte) {
	if !t.termios.LEnabled(linux.ECHO) || !t.termios.LEnabled(linux.ECHOE) {
		return
	}
	cols := 1
	if (erased < 0x20 || erased == 0x7f) && erased != '\t' {
		if t.termios.LEnabled(linux.ECHOCTL) {
			cols = 2
		} else {
			cols = 0
		}
	}
	for range cols {
		*dst = append(*dst, '\b', ' ', '\b')
	}
}

func (t *ttyState) eraseOneCharLocked(echo *[]byte) {
	if erased, ok := t.popLastCharLocked(); ok {
		t.echoEraseCharLocked(echo, erased)
	}
}

func (t *ttyState) eraseOneWordLocked(echo *[]byte) {
	seenWord := false
	for len(t.lineBuf) > 0 {
		last := t.lineBuf[len(t.lineBuf)-1]
		isWord := unicode.IsLetter(rune(last)) || unicode.IsDigit(rune(last)) || last == '_'
		if isWord {
			seenWord = true
		} else if seenWord {
			break
		}
		erased, ok := t.popLastCharLocked()
		if !ok {
			break
		}
		t.echoEraseCharLocked(echo, erased)
	}
}

func (t *ttyState) eraseLineLocked(echo *[]byte) {
	for len(t.lineBuf) > 0 {
		erased, ok := t.popLastCharLocked()
		if !ok {
			break
		}
		if t.termios.LEnabled(linux.ECHOK) {
			t.echoEraseCharLocked(echo, erased)
		}
	}
}

func (t *ttyState) consumeInput(chunk []byte) bool {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return false
	}
	if !t.rawHost {
		t.readBuf = append(t.readBuf, chunk...)
		t.mu.Unlock()
		t.wq.Notify(waiter.ReadableEvents)
		return true
	}

	var (
		echo       []byte
		sigs       []linux.Signal
		notifyRead bool
	)

	for _, b := range chunk {
		if t.termios.IEnabled(linux.ISTRIP) {
			b &= 0x7f
		}
		switch b {
		case '\r':
			if t.termios.IEnabled(linux.IGNCR) {
				continue
			}
			if t.termios.IEnabled(linux.ICRNL) {
				b = '\n'
			}
		case '\n':
			if t.termios.IEnabled(linux.INLCR) {
				b = '\r'
			}
		}
		if t.termios.IEnabled(linux.IUCLC) && b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}

		if t.termios.LEnabled(linux.ISIG) && b != 0 {
			var sig linux.Signal
			switch b {
			case t.cc(linux.VINTR):
				sig = linux.SIGINT
			case t.cc(linux.VQUIT):
				sig = linux.SIGQUIT
			case t.cc(linux.VSUSP):
				sig = linux.SIGTSTP
			}
			if sig != 0 {
				sigs = append(sigs, sig)
				if !t.termios.LEnabled(linux.NOFLSH) {
					t.lineBuf = t.lineBuf[:0]
					t.readBuf = t.readBuf[:0]
					t.pendingEOF = false
				}
				if t.termios.LEnabled(linux.ECHO) {
					if t.termios.LEnabled(linux.ECHOCTL) {
						echo = append(echo, '^', b+0x40)
					}
					t.appendOutputNewlineLocked(&echo)
				}
				continue
			}
		}

		if !t.termios.LEnabled(linux.ICANON) {
			t.readBuf = append(t.readBuf, b)
			notifyRead = true
			if t.termios.LEnabled(linux.ECHO) {
				t.appendEchoByteLocked(&echo, b)
			}
			continue
		}

		verase := t.cc(linux.VERASE)
		if b != 0 && (b == verase || (verase == 0x7f && b == '\b')) {
			t.eraseOneCharLocked(&echo)
			continue
		}
		if t.termios.LEnabled(linux.IEXTEN) && b != 0 && b == t.cc(linux.VWERASE) {
			t.eraseOneWordLocked(&echo)
			continue
		}
		if b != 0 && b == t.cc(linux.VKILL) {
			t.eraseLineLocked(&echo)
			continue
		}
		if b != 0 && b == t.cc(linux.VEOF) {
			if len(t.lineBuf) > 0 {
				t.readBuf = append(t.readBuf, t.lineBuf...)
				t.lineBuf = t.lineBuf[:0]
			} else {
				t.pendingEOF = true
			}
			notifyRead = true
			continue
		}

		t.lineBuf = append(t.lineBuf, b)
		if t.termios.LEnabled(linux.ECHO) {
			t.appendEchoByteLocked(&echo, b)
		} else if b == '\n' && t.termios.LEnabled(linux.ECHONL) {
			t.appendOutputNewlineLocked(&echo)
		}

		veol := t.cc(linux.VEOL)
		veol2 := t.cc(linux.VEOL2)
		if b == '\n' || (b != 0 && (b == veol || b == veol2)) {
			t.readBuf = append(t.readBuf, t.lineBuf...)
			t.lineBuf = t.lineBuf[:0]
			notifyRead = true
		}
	}
	t.mu.Unlock()

	if len(echo) > 0 && t.out != nil {
		t.outMu.Lock()
		_, _ = t.out.Write(echo)
		t.outMu.Unlock()
	}
	for _, sig := range sigs {
		t.signalForeground(sig)
	}
	if notifyRead {
		t.wq.Notify(waiter.ReadableEvents)
	}
	return true
}

func (t *ttyState) signalForeground(sig linux.Signal) {
	if t.ktty == nil {
		return
	}
	t.ktty.SignalForegroundProcessGroup(kernel.SignalInfoPriv(sig))
}

func (t *ttyState) read(ctx gvcontext.Context, dst usermem.IOSequence) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	t.mu.Lock()
	if len(t.readBuf) > 0 {
		count := min(int(dst.NumBytes()), len(t.readBuf))
		chunk := append([]byte(nil), t.readBuf[:count]...)
		t.readBuf = t.readBuf[count:]
		t.mu.Unlock()
		copied, err := dst.CopyOut(ctx, chunk)
		return int64(copied), err
	}
	if t.pendingEOF {
		t.pendingEOF = false
		t.mu.Unlock()
		return 0, io.EOF
	}
	if t.hostEOF {
		err := t.hostErr
		t.mu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	t.mu.Unlock()
	return 0, linuxerr.ErrWouldBlock
}

func (t *ttyState) readReadiness() waiter.EventMask {
	t.mu.Lock()
	defer t.mu.Unlock()
	var mask waiter.EventMask
	if len(t.readBuf) > 0 || t.pendingEOF || t.hostEOF {
		mask |= waiter.ReadableEvents
	}
	if t.hostEOF && len(t.readBuf) == 0 {
		mask |= waiter.EventHUp
	}
	return mask
}

func (t *ttyState) readableBytes() int32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return int32(len(t.readBuf))
}

func (t *ttyState) flushInput() {
	t.mu.Lock()
	t.lineBuf = t.lineBuf[:0]
	t.readBuf = t.readBuf[:0]
	t.pendingEOF = false
	t.mu.Unlock()
}

func (t *ttyState) shouldTranslateONLCR() bool {
	if !t.rawHost {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.termios.OEnabled(linux.OPOST) && t.termios.OEnabled(linux.ONLCR)
}

func (t *ttyState) setTermios(kt linux.KernelTermios, flushInput bool) {
	t.mu.Lock()
	wasCanon := t.termios.LEnabled(linux.ICANON)
	t.termios = kt
	if flushInput {
		t.lineBuf = t.lineBuf[:0]
		t.readBuf = t.readBuf[:0]
		t.pendingEOF = false
	} else if wasCanon && !t.termios.LEnabled(linux.ICANON) && len(t.lineBuf) > 0 {
		t.readBuf = append(t.readBuf, t.lineBuf...)
		t.lineBuf = t.lineBuf[:0]
	}
	notify := len(t.readBuf) > 0
	t.mu.Unlock()
	if notify {
		t.wq.Notify(waiter.ReadableEvents)
	}
}

func (t *ttyState) setWinsize(ws linux.Winsize) {
	t.mu.Lock()
	changed := t.winsize.Row != ws.Row || t.winsize.Col != ws.Col
	t.winsize = ws
	t.mu.Unlock()
	if changed {
		t.signalForeground(linux.SIGWINCH)
	}
}

func isHostTerminalReader(r io.Reader) bool {
	return isHostTerminal(r)
}

type stdioFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD

	reader io.Reader
	writer io.Writer
	tty    *ttyState
	// mu serializes the host reader or writer that every file description of
	// the stream shares.
	mu *sync.Mutex
}

func (f *stdioFD) Release(gvcontext.Context) {}

func (f *stdioFD) EventRegister(e *waiter.Entry) error {
	if f.tty != nil {
		f.tty.wq.EventRegister(e)
	}
	return nil
}

func (f *stdioFD) EventUnregister(e *waiter.Entry) {
	if f.tty != nil {
		f.tty.wq.EventUnregister(e)
	}
}

func (f *stdioFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	if f.tty == nil {
		return waiter.ReadableEvents | waiter.WritableEvents
	}
	var ready waiter.EventMask
	if f.writer != nil {
		ready |= waiter.WritableEvents
	}
	if f.reader != nil {
		ready |= f.tty.readReadiness()
	}
	return ready & mask
}

func (f *stdioFD) Epollable() bool {
	return f.tty != nil
}

func (f *stdioFD) Stat(_ gvcontext.Context, _ vfs.StatOptions) (linux.Statx, error) {
	if f.tty != nil {
		return linux.Statx{
			Mask:      linux.STATX_BASIC_STATS,
			Mode:      linux.S_IFCHR | 0o620,
			Nlink:     1,
			Blksize:   1024,
			Ino:       1,
			RdevMajor: linux.UNIX98_PTY_REPLICA_MAJOR,
			RdevMinor: 0,
		}, nil
	}
	return linux.Statx{
		Mask:      linux.STATX_BASIC_STATS,
		Mode:      linux.S_IFIFO | 0o666,
		Nlink:     1,
		Blksize:   4096,
		RdevMajor: 0,
		RdevMinor: 0,
	}, nil
}

func (f *stdioFD) SetStat(gvcontext.Context, vfs.SetStatOptions) error {
	return nil
}

func (f *stdioFD) Read(ctx gvcontext.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	if f.reader == nil {
		return 0, io.EOF
	}
	if f.tty != nil {
		return f.tty.read(ctx, dst)
	}
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	chunk := int(dst.NumBytes())
	if chunk > 64*1024 {
		chunk = 64 * 1024
	}
	buf := make([]byte, chunk)
	f.mu.Lock()
	n, rErr := f.reader.Read(buf)
	f.mu.Unlock()
	if n > 0 {
		copied, cErr := dst.CopyOut(ctx, buf[:n])
		if cErr != nil {
			return int64(copied), cErr
		}
		return int64(copied), nil
	}
	if rErr != nil {
		return 0, rErr
	}
	return 0, io.EOF
}

func (f *stdioFD) PRead(ctx gvcontext.Context, dst usermem.IOSequence, _ int64, opts vfs.ReadOptions) (int64, error) {
	return f.Read(ctx, dst, opts)
}

func translateONLCR(src []byte) []byte {
	var nlCount int
	for _, b := range src {
		if b == '\n' {
			nlCount++
		}
	}
	if nlCount == 0 {
		return src
	}
	out := make([]byte, 0, len(src)+nlCount)
	for _, b := range src {
		if b == '\n' {
			out = append(out, '\r', '\n')
		} else {
			out = append(out, b)
		}
	}
	return out
}

// Write copies guest output to the host writer. A host write failure returns
// EIO to the guest, so the guest never sees a successful write that the host
// dropped.
func (f *stdioFD) Write(ctx gvcontext.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	total := int(src.NumBytes())
	if total == 0 {
		return 0, nil
	}
	buf := make([]byte, total)
	n, inErr := src.CopyIn(ctx, buf)
	if n > 0 && f.writer != nil {
		out := buf[:n]
		if f.tty != nil && f.tty.shouldTranslateONLCR() {
			out = translateONLCR(out)
		}
		f.mu.Lock()
		_, wErr := f.writer.Write(out)
		f.mu.Unlock()
		if wErr != nil {
			return 0, linuxerr.EIO
		}
	}
	return int64(n), inErr
}

func (f *stdioFD) PWrite(ctx gvcontext.Context, src usermem.IOSequence, _ int64, opts vfs.WriteOptions) (int64, error) {
	return f.Write(ctx, src, opts)
}

func (f *stdioFD) Ioctl(ctx gvcontext.Context, _ usermem.IO, _ uintptr, args arch.SyscallArguments) (uintptr, error) {
	if f.tty == nil {
		return 0, linuxerr.ENOTTY
	}
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return 0, linuxerr.ENOTTY
	}

	switch cmd := args[1].Uint(); cmd {
	case linux.TCGETS:
		f.tty.mu.Lock()
		termios := f.tty.termios.ToTermios()
		f.tty.mu.Unlock()
		_, err := termios.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TCSETS, linux.TCSETSW, linux.TCSETSF:
		var termios linux.Termios
		if _, err := termios.CopyIn(t, args[2].Pointer()); err != nil {
			return 0, err
		}
		f.tty.mu.Lock()
		kt := f.tty.termios
		f.tty.mu.Unlock()
		kt.FromTermios(termios)
		f.tty.setTermios(kt, cmd == linux.TCSETSF)
		return 0, nil
	case linux.TCGETS2:
		f.tty.mu.Lock()
		kt := f.tty.termios
		f.tty.mu.Unlock()
		_, err := kt.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TCSETS2, linux.TCSETSW2, linux.TCSETSF2:
		var kt linux.KernelTermios
		if _, err := kt.CopyIn(t, args[2].Pointer()); err != nil {
			return 0, err
		}
		f.tty.setTermios(kt, cmd == linux.TCSETSF2)
		return 0, nil
	case linux.TIOCGWINSZ:
		f.tty.mu.Lock()
		ws := f.tty.winsize
		f.tty.mu.Unlock()
		_, err := ws.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TIOCSWINSZ:
		var ws linux.Winsize
		if _, err := ws.CopyIn(t, args[2].Pointer()); err != nil {
			return 0, err
		}
		f.tty.setWinsize(ws)
		return 0, nil
	case linux.TIOCGPGRP:
		if f.tty.ktty != nil {
			if pgid, err := t.ThreadGroup().ForegroundProcessGroupID(f.tty.ktty); err == nil {
				ret := primitive.Int32(pgid)
				_, cErr := ret.CopyOut(t, args[2].Pointer())
				return 0, cErr
			}
		}
		f.tty.mu.Lock()
		fg := f.tty.fgPgrp
		f.tty.mu.Unlock()
		ret := primitive.Int32(fg)
		_, err := ret.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TIOCSPGRP:
		var pgid primitive.Int32
		if _, err := pgid.CopyIn(t, args[2].Pointer()); err != nil {
			return 0, err
		}
		f.tty.mu.Lock()
		f.tty.fgPgrp = int32(pgid)
		f.tty.mu.Unlock()
		if f.tty.ktty != nil && t.ThreadGroup().TTY() == f.tty.ktty {
			return 0, t.ThreadGroup().SetForegroundProcessGroupID(ctx, f.tty.ktty, kernel.ProcessGroupID(pgid))
		}
		return 0, nil
	case linux.TIOCGSID:
		if f.tty.ktty != nil {
			if sid, err := t.ThreadGroup().SessionID(f.tty.ktty, false); err == nil {
				ret := primitive.Int32(sid)
				_, cErr := ret.CopyOut(t, args[2].Pointer())
				return 0, cErr
			}
		}
		f.tty.mu.Lock()
		sid := f.tty.session
		f.tty.mu.Unlock()
		ret := primitive.Int32(sid)
		_, err := ret.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TIOCSCTTY:
		if f.tty.ktty != nil {
			steal := args[2].Int() == 1
			_ = t.ThreadGroup().SetControllingTTY(ctx, f.tty.ktty, steal, true)
		}
		return 0, nil
	case linux.TIOCNOTTY:
		if f.tty.ktty != nil {
			_ = t.ThreadGroup().ReleaseControllingTTY(ctx, f.tty.ktty)
		}
		return 0, nil
	case linux.TIOCGPTN:
		ret := primitive.Uint32(0)
		_, err := ret.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.FIONREAD:
		ret := primitive.Int32(f.tty.readableBytes())
		_, err := ret.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TCFLSH:
		switch args[2].Uint() {
		case linux.TCIFLUSH, linux.TCIOFLUSH:
			f.tty.flushInput()
		case linux.TCOFLUSH:
		default:
			return 0, linuxerr.EINVAL
		}
		return 0, nil
	case linux.TCSBRK, linux.TIOCSPTLCK:
		return 0, nil
	default:
		return 0, linuxerr.ENOTTY
	}
}

// createKernelMemoryFile creates the Sentry MemoryFile on an anonymous host
// backing file. New calls it before the host lockdown because the lockdown
// denies new host file creation.
func createKernelMemoryFile() (*pgalloc.MemoryFile, error) {
	const memFileName = "gvx-kernel-memory"
	memFD, err := memutil.CreateMemFD(memFileName, 0)
	if err != nil {
		return nil, fmt.Errorf("gvx: create memory backing file: %w", err)
	}
	memFile := os.NewFile(uintptr(memFD), memFileName)
	mf, err := pgalloc.NewMemoryFile(memFile, pgalloc.MemoryFileOpts{})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("gvx: init pgalloc.MemoryFile: %w", err), memFile.Close())
	}
	return mf, nil
}

func createSandboxLimitSet() (*limits.LimitSet, error) {
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		return nil, err
	}
	ls.SetUnchecked(limits.NumberOfFiles, limits.Limit{Cur: 65536, Max: 65536})
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Data, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Stack, limits.Limit{Cur: 8 * 1024 * 1024, Max: limits.Infinity})
	ls.SetUnchecked(limits.ProcessCount, limits.Limit{Cur: 4096, Max: 4096})
	return ls, nil
}

func (s *Sandbox) runWithKernel(ctx context.Context, argv []string) (int, error) {
	if len(argv) == 0 {
		return 1, fmt.Errorf("gvx: empty command vector")
	}

	s.mu.Lock()
	mf := s.memFile
	s.memFile = nil
	s.mu.Unlock()
	if mf == nil {
		return 1, errRunConsumed
	}
	defer mf.Destroy()

	k := &kernel.Kernel{
		Platform: s.plat,
	}
	k.SetMemoryFile(mf)

	vdso, err := loader.PrepareVDSO(mf)
	if err != nil {
		return 1, fmt.Errorf("gvx: prepare VDSO: %w", err)
	}

	tk := kernel.NewTimekeeper()
	paramsRange, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		return 1, fmt.Errorf("gvx: allocate VDSO param page: %w", err)
	}
	vdsoParams := kernel.NewVDSOParamPage(mf, paramsRange)
	tk.SetClocks(sentrytime.NewCalibratedClocks(false), vdsoParams)
	defer tk.Destroy()

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var rootNetNS *inet.Namespace
	if s.netStack != nil {
		inetStack := netstack.NewStack(s.netStack, 1)
		rootNetNS = inet.NewRootNamespace(inetStack, nil, creds.UserNamespace)
	}

	maxCPUs := runtime.NumCPU()
	if maxCPUs < 1 {
		maxCPUs = 1
	}

	if err := k.Init(kernel.InitKernelArgs{
		FeatureSet:           cpuid.HostFeatureSet(),
		Timekeeper:           tk,
		RootUserNamespace:    creds.UserNamespace,
		RootNetworkNamespace: rootNetNS,
		ApplicationCores:     uint(guestCPUs(s.cfg.Resources.CPUMillis, maxCPUs)),
		Vdso:                 vdso,
		VdsoParams:           vdsoParams,
		RootUTSNamespace:     kernel.NewUTSNamespace(s.hostname(), "localdomain", creds.UserNamespace),
		RootIPCNamespace:     kernel.NewIPCNamespace(creds.UserNamespace),
		RootPIDNamespace:     kernel.NewRootPIDNamespace(creds.UserNamespace),
		MaxFDLimit:           kernel.MaxFdLimit,
		Cgroup2FSInit:        cgroup2fs.NewFilesystem,
	}); err != nil {
		return 1, fmt.Errorf("gvx: init Sentry kernel: %w", err)
	}

	vfsObj := k.VFS()
	vfsObj.MustRegisterFilesystemType("erofs", erofs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType("overlay", overlay.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("proc", proc.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("sysfs", sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("devtmpfs", dev.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("devpts", &devpts.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType("cgroup2", cgroup2fs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(hostfs.Name, hostfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(ext4lite.Name, ext4lite.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	if ext4lite.Name != "ext4lite" {
		vfsObj.MustRegisterFilesystemType("ext4lite", ext4lite.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	}

	if err := memdev.Register(vfsObj); err != nil {
		return 1, fmt.Errorf("gvx: register memdev: %w", err)
	}
	if err := ttydev.Register(vfsObj); err != nil {
		return 1, fmt.Errorf("gvx: register ttydev: %w", err)
	}

	sctx := k.SupervisorContext()

	mntns, err := s.buildKernelRootMountNamespace(sctx, vfsObj, creds)
	if err != nil {
		return 1, err
	}
	defer mntns.DecRef(sctx)

	root := mntns.Root(sctx)
	defer root.DecRef(sctx)
	sctxWithRoot := vfs.WithRoot(sctx, root)

	if err := s.setupKernelSubmountsAndFiles(sctxWithRoot, vfsObj, creds, root); err != nil {
		return 1, err
	}

	execPath, err := resolveGuestExecutable(sctxWithRoot, vfsObj, creds, root, argv[0], s.cfg.Envv)
	if err != nil {
		return 1, err
	}
	var (
		cachedExecHeader []byte
		cachedExecErr    error
		cachedExecOnce   sync.Once
	)
	readGuest := func(path string, maxBytes int) ([]byte, error) {
		if path == execPath && maxBytes == elfProbeBytes {
			cachedExecOnce.Do(func() {
				cachedExecHeader, cachedExecErr = readGuestFile(sctxWithRoot, vfsObj, creds, root, path, maxBytes)
			})
			return cachedExecHeader, cachedExecErr
		}
		return readGuestFile(sctxWithRoot, vfsObj, creds, root, path, maxBytes)
	}
	user, procCreds, err := s.guestUser(sctxWithRoot, vfsObj, creds, root)
	if err != nil {
		return 1, err
	}

	fdTable := k.NewFDTable()
	defer fdTable.DecRef(sctx)

	var tty *ttyState
	if s.cfg.TTY || isHostTerminalReader(s.cfg.Stdin) {
		restoreTerm, rawHost := enterHostRawMode(s.cfg.Stdin, s.cfg.Stdout)
		defer restoreTerm()
		rows, cols, _ := hostTerminalSize(s.cfg.Stdin, s.cfg.Stdout)
		tty = newTTYState(s.cfg.Stdin, s.cfg.Stdout, rawHost, rows, cols)
		stopWinch := watchHostWinch(ctx, s.cfg.Stdin, s.cfg.Stdout, func(r, c uint16) {
			tty.setWinsize(linux.Winsize{Row: r, Col: c})
		})
		defer stopWinch()
		defer tty.stop()
	}

	stdio, err := openStdioFDs(sctx, vfsObj, creds, s.cfg.Stdin, s.cfg.Stdout, s.cfg.Stderr, tty)
	if err != nil {
		return 1, err
	}
	_, fdErr := fdTable.NewFDs(sctx, 0, stdio[:], kernel.FDFlags{})
	for _, fd := range stdio {
		fd.DecRef(sctx)
	}
	if fdErr != nil {
		return 1, fmt.Errorf("gvx: bind stdio FDs: %w", fdErr)
	}

	ls, err := createSandboxLimitSet()
	if err != nil {
		return 1, err
	}

	workDir := s.cfg.WorkDir
	if (workDir == "" || workDir == "/") && s.resolvedImg != nil && s.resolvedImg.Config.WorkingDir != "" {
		workDir = s.resolvedImg.Config.WorkingDir
	}
	if workDir == "" {
		workDir = "/"
	}

	envv := finalizeEnv(s.cfg.Envv, guestEnvDefaults{Home: user.Home, Hostname: s.hostname(), TTY: tty != nil})

	var procTTY *kernel.TTY
	if tty != nil {
		procTTY = tty.ktty
	}

	mntns.IncRef()
	procArgs := kernel.CreateProcessArgs{
		Filename:             execPath,
		Argv:                 argv,
		Envv:                 envv,
		WorkingDirectory:     workDir,
		Credentials:          procCreds,
		FDTable:              fdTable,
		MountNamespace:       mntns,
		Umask:                0o022,
		Limits:               ls,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         k.RootUTSNamespace(),
		IPCNamespace:         k.RootIPCNamespace(),
		Origin:               kernel.OriginExec,
		ContainerID:          cmp.Or(s.cfg.Name, "gvx-default"),
		PIDNamespace:         k.RootPIDNamespace(),
		TTY:                  procTTY,
	}

	tg, _, err := k.CreateProcess(procArgs)
	if err != nil {
		if hint := s.nonPIEHintForGuestFile(readGuest, execPath); hint != "" {
			err = fmt.Errorf("%w; %s", err, hint)
		}
		return 1, fmt.Errorf("gvx: create guest process %q: %w", execPath, err)
	}

	if tty != nil {
		tty.startPump()
	}

	if err := k.Start(); err != nil {
		return 1, fmt.Errorf("gvx: start Sentry kernel: %w", err)
	}

	_ = takeEngineFault()
	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		case <-doneCh:
		}
	}()

	var memoryExceeded atomic.Bool
	if limit := s.cfg.Resources.MemoryBytes; limit > 0 {
		guard := memoryGuard{
			limit: uint64(limit),
			// The accounting counts a committed page only after a scan of the
			// memory file. UpdateUsage limits its own scan rate.
			used: func() uint64 {
				_ = mf.UpdateUsage(nil)
				return usage.MemoryAccounting.Total()
			},
			interval: memoryPollInterval,
			kill: func() {
				memoryExceeded.Store(true)
				_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
			},
		}
		guardCtx, stopGuard := context.WithCancel(ctx)
		guardDone := make(chan struct{})
		go func() {
			defer close(guardDone)
			guard.run(guardCtx)
		}()
		defer func() {
			stopGuard()
			<-guardDone
		}()
	}

	k.WaitExited()
	close(doneCh)
	k.Pause()

	if ctx.Err() != nil {
		return 1, ctx.Err()
	}
	if memoryExceeded.Load() {
		return 137, ErrMemoryLimit
	}

	ws := tg.ExitStatus()
	if ws.Signaled() && ws.TerminationSignal() == linux.SIGKILL {
		if cause := takeEngineFault(); cause != "" {
			return 128 + int(linux.SIGKILL), engineFaultError(cause)
		}
	}
	if ws.Signaled() {
		return 128 + int(ws.TerminationSignal()), nil
	}
	return int(ws.ExitStatus()), nil
}

func (s *Sandbox) buildKernelRootMountNamespace(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) (*vfs.MountNamespace, error) {
	if len(s.layerHandles) == 0 {
		return vfsObj.NewMountNamespace(sctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
	}

	var lowerRoots []vfs.VirtualDentry
	cleanupLowers := func() {
		for _, lr := range lowerRoots {
			lr.DecRef(sctx)
		}
	}

	// overlay.FilesystemOptions.LowerRoots[0] is the top-most lower layer.
	for i := len(s.layerHandles) - 1; i >= 0; i-- {
		dupHH, err := s.layerHandles[i].Dup()
		if err != nil {
			cleanupLowers()
			return nil, fmt.Errorf("gvx: dup EROFS layer handle: %w", err)
		}
		dupFD, err := dupHH.Release()
		if err != nil {
			_ = dupHH.Close()
			cleanupLowers()
			return nil, fmt.Errorf("gvx: release dup EROFS layer handle: %w", err)
		}
		fs, rootDentry, err := erofs.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{
			Data: fmt.Sprintf("ifd=%d", int(dupFD)),
		})
		if err != nil {
			cleanupLowers()
			return nil, fmt.Errorf("gvx: mount EROFS layer %d: %w", i, err)
		}
		mnt := vfsObj.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{ReadOnly: true})
		fs.DecRef(sctx)
		lowerRoots = append(lowerRoots, vfs.MakeVirtualDentry(mnt, rootDentry))
	}

	upperFS, upperRootDentry, err := tmpfs.FilesystemType{}.GetFilesystem(sctx, vfsObj, creds, "", vfs.GetFilesystemOptions{})
	if err != nil {
		cleanupLowers()
		return nil, fmt.Errorf("gvx: create tmpfs upper layer: %w", err)
	}
	upperMnt := vfsObj.NewDisconnectedMount(upperFS, upperRootDentry, &vfs.MountOptions{})
	upperFS.DecRef(sctx)
	upperRoot := vfs.MakeVirtualDentry(upperMnt, upperRootDentry)

	mntns, err := vfsObj.NewMountNamespace(sctx, creds, "", "overlay", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: overlay.FilesystemOptions{
				UpperRoot:  upperRoot,
				LowerRoots: lowerRoots,
			},
		},
	}, nil)
	upperRoot.DecRef(sctx)
	cleanupLowers()
	if err != nil {
		return nil, fmt.Errorf("gvx: create overlay root mount namespace: %w", err)
	}
	return mntns, nil
}

func (s *Sandbox) setupKernelSubmountsAndFiles(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) error {
	// The tmpfs that holds the writes of the guest has the mode 01777, and the
	// overlay shows it as the mode of "/". A guest user that is not root could
	// then create files in "/". Images use the mode 0755 for "/".
	if err := vfsObj.SetStatAt(sctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: makeFPath("/")}, &vfs.SetStatOptions{
		Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: 0o755},
	}); err != nil {
		return fmt.Errorf("gvx: set the mode of the guest root: %w", err)
	}
	for _, dir := range []string{"/proc", "/sys", "/dev", "/etc", "/root", "/workspace", "/bin", "/usr/bin"} {
		if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, dir, 0o755); err != nil {
			return fmt.Errorf("gvx: create guest directory %s: %w", dir, err)
		}
	}
	// Programs expect a sticky, world-writable /tmp. An image that has one keeps it.
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/tmp", 0o1777); err != nil {
		return fmt.Errorf("gvx: create guest directory /tmp: %w", err)
	}

	mountSubfs := func(target, fsName string, opts *vfs.MountOptions) error {
		pop := vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  makeFPath(target),
		}
		if _, err := vfsObj.MountAt(sctx, creds, "", &pop, fsName, opts); err != nil {
			return fmt.Errorf("gvx: mount %s at %s: %w", fsName, target, err)
		}
		return nil
	}
	dataOpts := func(data string) *vfs.MountOptions {
		return &vfs.MountOptions{GetFilesystemOptions: vfs.GetFilesystemOptions{Data: data}}
	}
	if err := mountSubfs("/proc", "proc", dataOpts("")); err != nil {
		return err
	}
	if err := mountSubfs("/sys", "sysfs", dataOpts("")); err != nil {
		return err
	}
	if err := mountSubfs("/dev", "devtmpfs", dataOpts("")); err != nil {
		return err
	}
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/dev/pts", 0o755); err != nil {
		return fmt.Errorf("gvx: create guest directory /dev/pts: %w", err)
	}
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, "/dev/shm", 0o1777); err != nil {
		return fmt.Errorf("gvx: create guest directory /dev/shm: %w", err)
	}
	if err := mountSubfs("/dev/pts", "devpts", dataOpts("ptmxmode=0666,mode=0620")); err != nil {
		return err
	}
	if err := mountSubfs("/dev/shm", "tmpfs", dataOpts("")); err != nil {
		return err
	}

	// Populate default /etc files if absent so getpwuid, localhost, and DNS work.
	for _, f := range []struct {
		path string
		data string
	}{
		{"/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n"},
		{"/etc/group", "root:x:0:root\nnogroup:x:65534:\n"},
		{"/etc/hosts", "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + netbackend.HostGatewayIPv4 + "\thost.docker.internal\n" + netbackend.DefaultGuestIPv4 + "\tgvx\n"},
		{"/etc/resolv.conf", "nameserver " + netbackend.HostDNSIPv4 + "\n"},
	} {
		if err := ensureGuestFileIfAbsent(sctx, vfsObj, creds, root, f.path, []byte(f.data), 0o644); err != nil {
			return fmt.Errorf("gvx: create guest file %s: %w", f.path, err)
		}
	}

	if err := s.writeGuestHostFiles(sctx, vfsObj, creds, root); err != nil {
		return err
	}

	// s.mounts is ordered by increasing path depth, so a mount point below
	// another mount exists in that mount before the guest mounts there.
	for _, m := range s.mounts {
		if err := s.mountUserMount(sctx, vfsObj, creds, root, m, mountSubfs); err != nil {
			return err
		}
	}

	if s.cfg.ReadOnlyRoot {
		if err := vfsObj.SetMountReadOnly(root.Mount(), true); err != nil {
			return fmt.Errorf("gvx: mount the root read-only: %w", err)
		}
	}
	return nil
}

// mountUserMount creates the guest mount point of m and mounts it there. The
// mount point is a directory, or an empty regular file for a file mount. A bind
// mount or a hostfs volume uses the VFS2 hostfs driver. An ext4lite volume uses
// the ext4lite driver on its open image. A tmpfs mount uses the Sentry tmpfs
// with a size limit and mode 1777.
func (s *Sandbox) mountUserMount(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, m sandboxMount, mountSubfs func(target, fsName string, opts *vfs.MountOptions) error) error {
	dirMode := linux.FileMode(0o755)
	if m.Kind == MountTmpfs {
		dirMode = 0o1777
	}
	if m.hostFile {
		if err := vfsEnsureEmptyFile(sctx, vfsObj, creds, root, m.GuestPath, 0o644); err != nil {
			return fmt.Errorf("gvx: create guest file %s: %w", m.GuestPath, err)
		}
	} else if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, m.GuestPath, dirMode); err != nil {
		return fmt.Errorf("gvx: create guest directory %s: %w", m.GuestPath, err)
	}
	if m.Kind == MountTmpfs {
		return mountSubfs(m.GuestPath, "tmpfs", &vfs.MountOptions{
			ReadOnly:             m.ReadOnly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{Data: tmpfsMountData(m.TmpfsSizeBytes)},
		})
	}
	if m.volume != nil {
		return mountSubfs(m.GuestPath, ext4lite.Name, &vfs.MountOptions{
			ReadOnly: m.ReadOnly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalData: ext4lite.InternalFilesystemOptions{Volume: m.volume},
			},
		})
	}
	return mountSubfs(m.GuestPath, hostfs.Name, &vfs.MountOptions{
		ReadOnly: m.workspace.ReadOnly(),
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: hostfs.InternalFilesystemOptions{Workspace: m.workspace},
		},
	})
}

// tmpfsMountData returns the mount data of a tmpfs mount. A zero size keeps
// the default limit of the Sentry tmpfs.
func tmpfsMountData(sizeBytes int64) string {
	if sizeBytes == 0 {
		return "mode=1777"
	}
	return fmt.Sprintf("size=%d,mode=1777", sizeBytes)
}

func vfsWriteFile(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, data []byte, mode linux.FileMode) error {
	dir := path.Dir(guestPath)
	if dir != "/" && dir != "." {
		if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, dir, 0o755); err != nil {
			return err
		}
	}
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath)}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC,
		Mode:  mode,
	})
	if err != nil {
		return err
	}
	defer fd.DecRef(sctx)
	if len(data) == 0 {
		return nil
	}
	n, err := fd.Write(sctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		return err
	}
	if n != int64(len(data)) {
		return fmt.Errorf("short write: %d of %d bytes", n, len(data))
	}
	return nil
}

func ensureGuestFileIfAbsent(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, data []byte, mode linux.FileMode) error {
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath), FollowFinalSymlink: true}
	if st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_SIZE}); err == nil && st.Size > 0 {
		return nil
	}
	return vfsWriteFile(sctx, vfsObj, creds, root, guestPath, data, mode)
}

// vfsEnsureDirAll creates dirPath and its missing parents. An existing
// component must be a directory.
func vfsEnsureDirAll(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, dirPath string, mode linux.FileMode) error {
	cleaned := path.Clean("/" + strings.TrimPrefix(dirPath, "/"))
	if cleaned == "/" {
		return nil
	}
	cur := ""
	for _, p := range strings.Split(strings.TrimPrefix(cleaned, "/"), "/") {
		cur += "/" + p
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(cur), FollowFinalSymlink: true}
		st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
		if err == nil {
			if st.Mode&linux.S_IFMT != linux.S_IFDIR {
				return fmt.Errorf("%s: %w", cur, linuxerr.ENOTDIR)
			}
			continue
		}
		if !linuxerr.Equals(linuxerr.ENOENT, err) {
			return fmt.Errorf("stat %s: %w", cur, err)
		}
		mkPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(cur)}
		if err := vfsObj.MkdirAt(sctx, creds, &mkPop, &vfs.MkdirOptions{Mode: mode}); err != nil {
			return fmt.Errorf("mkdir %s: %w", cur, err)
		}
	}
	return nil
}

// vfsEnsureEmptyFile creates an empty regular file at guestPath and the
// missing parent directories. An existing regular file stays as it is. Any
// other existing file type is an error, because a file mount needs a file.
func vfsEnsureEmptyFile(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, mode linux.FileMode) error {
	if err := vfsEnsureDirAll(sctx, vfsObj, creds, root, path.Dir(guestPath), 0o755); err != nil {
		return err
	}
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath)}
	st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err == nil {
		if st.Mode&linux.S_IFMT != linux.S_IFREG {
			return fmt.Errorf("%s: not a regular file", guestPath)
		}
		return nil
	}
	if !linuxerr.Equals(linuxerr.ENOENT, err) {
		return fmt.Errorf("stat %s: %w", guestPath, err)
	}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{
		Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_EXCL,
		Mode:  mode,
	})
	if err != nil {
		return fmt.Errorf("create %s: %w", guestPath, err)
	}
	fd.DecRef(sctx)
	return nil
}

func resolveGuestExecutable(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, cmd string, envv []string) (string, error) {
	checkPath := func(candidate string) bool {
		pop := vfs.PathOperation{
			Root:               root,
			Start:              root,
			Path:               makeFPath(candidate),
			FollowFinalSymlink: true,
		}
		st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE | linux.STATX_MODE})
		if err != nil {
			return false
		}
		return (st.Mode & linux.S_IFMT) == linux.S_IFREG
	}

	if strings.Contains(cmd, "/") {
		if checkPath(cmd) {
			return cmd, nil
		}
		return "", fmt.Errorf("gvx: executable %q not found in guest rootfs", cmd)
	}

	pathEnv := defaultPath
	for _, kv := range envv {
		if after, ok := strings.CutPrefix(kv, "PATH="); ok && after != "" {
			pathEnv = after
			break
		}
	}

	for _, dir := range strings.Split(pathEnv, ":") {
		if dir == "" {
			dir = "/"
		}
		candidate := path.Join(dir, cmd)
		if checkPath(candidate) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("gvx: executable %q not found in PATH (%s)", cmd, pathEnv)
}

func makeFPath(p string) fspath.Path {
	return fspath.Parse(p)
}
