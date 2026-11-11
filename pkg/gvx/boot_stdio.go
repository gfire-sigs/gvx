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
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

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
	t.mu.Lock()
	in := t.in
	out := t.out
	t.mu.Unlock()
	fd := &stdioFD{
		stream: stdioStreamCTTY,
		reader: in,
		writer: out,
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

func (t *ttyState) ensurePumpStarted() {
	t.mu.Lock()
	canStart := !t.pumpStarted && !t.stopped && !t.hostEOF && t.in != nil
	t.mu.Unlock()
	if canStart {
		t.startPump()
	}
}

func (t *ttyState) startPump() {
	t.mu.Lock()
	if t.pumpStarted || t.stopped {
		t.mu.Unlock()
		return
	}
	t.pumpStarted = true
	in := t.in
	t.mu.Unlock()
	if in == nil {
		t.finishInput(io.EOF)
		return
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := in.Read(buf)
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
	in := t.in
	t.mu.Unlock()
	if d, ok := in.(interface{ SetReadDeadline(time.Time) error }); ok {
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

	for _, rawByte := range chunk {
		b, skip := t.translateInputByteLocked(rawByte)
		if skip {
			continue
		}
		if sig, matched := t.trySignalCharLocked(b, &echo); matched {
			sigs = append(sigs, sig)
			continue
		}
		if !t.termios.LEnabled(linux.ICANON) {
			t.readBuf = append(t.readBuf, b)
			notifyRead = true
			if t.termios.LEnabled(linux.ECHO) {
				t.appendEchoByteLocked(&echo, b)
			}
			continue
		}
		if t.consumeCanonicalByteLocked(b, &echo) {
			notifyRead = true
		}
	}
	out := t.out
	t.mu.Unlock()

	if len(echo) > 0 && out != nil {
		t.outMu.Lock()
		_, _ = out.Write(echo)
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

func (t *ttyState) translateInputByteLocked(b byte) (byte, bool) {
	if t.termios.IEnabled(linux.ISTRIP) {
		b &= 0x7f
	}
	switch b {
	case '\r':
		if t.termios.IEnabled(linux.IGNCR) {
			return 0, true
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
	return b, false
}

func (t *ttyState) trySignalCharLocked(b byte, echo *[]byte) (linux.Signal, bool) {
	if !t.termios.LEnabled(linux.ISIG) || b == 0 {
		return 0, false
	}
	var sig linux.Signal
	switch b {
	case t.cc(linux.VINTR):
		sig = linux.SIGINT
	case t.cc(linux.VQUIT):
		sig = linux.SIGQUIT
	case t.cc(linux.VSUSP):
		sig = linux.SIGTSTP
	default:
		return 0, false
	}
	if !t.termios.LEnabled(linux.NOFLSH) {
		t.lineBuf = t.lineBuf[:0]
		t.readBuf = t.readBuf[:0]
		t.pendingEOF = false
	}
	if t.termios.LEnabled(linux.ECHO) {
		if t.termios.LEnabled(linux.ECHOCTL) {
			*echo = append(*echo, '^', b+0x40)
		}
		t.appendOutputNewlineLocked(echo)
	}
	return sig, true
}

func (t *ttyState) consumeCanonicalByteLocked(b byte, echo *[]byte) bool {
	verase := t.cc(linux.VERASE)
	if b != 0 && (b == verase || (verase == 0x7f && b == '\b')) {
		t.eraseOneCharLocked(echo)
		return false
	}
	if t.termios.LEnabled(linux.IEXTEN) && b != 0 && b == t.cc(linux.VWERASE) {
		t.eraseOneWordLocked(echo)
		return false
	}
	if b != 0 && b == t.cc(linux.VKILL) {
		t.eraseLineLocked(echo)
		return false
	}
	if b != 0 && b == t.cc(linux.VEOF) {
		if len(t.lineBuf) > 0 {
			t.readBuf = append(t.readBuf, t.lineBuf...)
			t.lineBuf = t.lineBuf[:0]
		} else {
			t.pendingEOF = true
		}
		return true
	}

	t.lineBuf = append(t.lineBuf, b)
	if t.termios.LEnabled(linux.ECHO) {
		t.appendEchoByteLocked(echo, b)
	} else if b == '\n' && t.termios.LEnabled(linux.ECHONL) {
		t.appendOutputNewlineLocked(echo)
	}

	veol := t.cc(linux.VEOL)
	veol2 := t.cc(linux.VEOL2)
	if b == '\n' || (b != 0 && (b == veol || b == veol2)) {
		t.readBuf = append(t.readBuf, t.lineBuf...)
		t.lineBuf = t.lineBuf[:0]
		return true
	}
	return false
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
	t.ensurePumpStarted()
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

func (f *stdioFD) Release(gvcontext.Context) {}

func (f *stdioFD) EventRegister(e *waiter.Entry) error {
	if f.tty != nil {
		f.tty.wq.EventRegister(e)
		f.tty.ensurePumpStarted()
	}
	if f.pump != nil {
		f.pump.register(e)
	}
	return nil
}

func (f *stdioFD) EventUnregister(e *waiter.Entry) {
	if f.tty != nil {
		f.tty.wq.EventUnregister(e)
	}
	if f.pump != nil {
		f.pump.wq.EventUnregister(e)
	}
}

func (f *stdioFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	if f.pump != nil {
		return f.pump.readiness() & mask
	}
	if f.tty == nil {
		return waiter.ReadableEvents | waiter.WritableEvents
	}
	var ready waiter.EventMask
	if f.writer != nil {
		ready |= waiter.WritableEvents
	}
	if f.reader != nil || f.vfsfd.IsReadable() {
		ready |= f.tty.readReadiness()
	}
	return ready & mask
}

func (f *stdioFD) Epollable() bool {
	return f.tty != nil || f.pump != nil
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
	if f.tty != nil {
		return f.tty.read(ctx, dst)
	}
	if f.pump != nil {
		return f.pump.read(ctx, dst)
	}
	if f.reader == nil {
		return 0, io.EOF
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

	cmd := args[1].Uint()
	switch cmd {
	case linux.TCGETS, linux.TCSETS, linux.TCSETSW, linux.TCSETSF,
		linux.TCGETS2, linux.TCSETS2, linux.TCSETSW2, linux.TCSETSF2:
		return 0, f.tty.ioctlTermios(t, cmd, args[2].Pointer())
	case linux.TIOCGWINSZ, linux.TIOCSWINSZ:
		return 0, f.tty.ioctlWinsize(t, cmd, args[2].Pointer())
	case linux.TIOCGPGRP, linux.TIOCSPGRP, linux.TIOCGSID:
		return 0, f.tty.ioctlProcessGroup(ctx, t, cmd, args[2].Pointer())
	case linux.TIOCSCTTY, linux.TIOCNOTTY, linux.TIOCGPTN, linux.FIONREAD, linux.TCFLSH:
		return 0, f.tty.ioctlControl(ctx, t, cmd, args[2])
	case linux.TCSBRK, linux.TIOCSPTLCK:
		return 0, nil
	default:
		return 0, linuxerr.ENOTTY
	}
}

func (t *ttyState) ioctlTermios(tsk *kernel.Task, cmd uint32, argPtr hostarch.Addr) error {
	switch cmd {
	case linux.TCGETS:
		t.mu.Lock()
		termios := t.termios.ToTermios()
		t.mu.Unlock()
		_, err := termios.CopyOut(tsk, argPtr)
		return err
	case linux.TCSETS, linux.TCSETSW, linux.TCSETSF:
		var termios linux.Termios
		if _, err := termios.CopyIn(tsk, argPtr); err != nil {
			return err
		}
		t.mu.Lock()
		kt := t.termios
		t.mu.Unlock()
		kt.FromTermios(termios)
		t.setTermios(kt, cmd == linux.TCSETSF)
		return nil
	case linux.TCGETS2:
		t.mu.Lock()
		kt := t.termios
		t.mu.Unlock()
		_, err := kt.CopyOut(tsk, argPtr)
		return err
	default:
		var kt linux.KernelTermios
		if _, err := kt.CopyIn(tsk, argPtr); err != nil {
			return err
		}
		t.setTermios(kt, cmd == linux.TCSETSF2)
		return nil
	}
}

func (t *ttyState) ioctlWinsize(tsk *kernel.Task, cmd uint32, argPtr hostarch.Addr) error {
	if cmd == linux.TIOCGWINSZ {
		t.mu.Lock()
		ws := t.winsize
		t.mu.Unlock()
		_, err := ws.CopyOut(tsk, argPtr)
		return err
	}
	var ws linux.Winsize
	if _, err := ws.CopyIn(tsk, argPtr); err != nil {
		return err
	}
	t.setWinsize(ws)
	return nil
}

func (t *ttyState) ioctlProcessGroup(ctx gvcontext.Context, tsk *kernel.Task, cmd uint32, argPtr hostarch.Addr) error {
	switch cmd {
	case linux.TIOCGPGRP:
		if t.ktty != nil {
			if pgid, err := tsk.ThreadGroup().ForegroundProcessGroupID(t.ktty); err == nil {
				ret := primitive.Int32(pgid)
				_, cErr := ret.CopyOut(tsk, argPtr)
				return cErr
			}
		}
		t.mu.Lock()
		fg := t.fgPgrp
		t.mu.Unlock()
		ret := primitive.Int32(fg)
		_, err := ret.CopyOut(tsk, argPtr)
		return err
	case linux.TIOCSPGRP:
		var pgid primitive.Int32
		if _, err := pgid.CopyIn(tsk, argPtr); err != nil {
			return err
		}
		t.mu.Lock()
		t.fgPgrp = int32(pgid)
		t.mu.Unlock()
		if t.ktty != nil && tsk.ThreadGroup().TTY() == t.ktty {
			return tsk.ThreadGroup().SetForegroundProcessGroupID(ctx, t.ktty, kernel.ProcessGroupID(pgid))
		}
		return nil
	default:
		if t.ktty != nil {
			if sid, err := tsk.ThreadGroup().SessionID(t.ktty, false); err == nil {
				ret := primitive.Int32(sid)
				_, cErr := ret.CopyOut(tsk, argPtr)
				return cErr
			}
		}
		t.mu.Lock()
		sid := t.session
		t.mu.Unlock()
		ret := primitive.Int32(sid)
		_, err := ret.CopyOut(tsk, argPtr)
		return err
	}
}

func (t *ttyState) ioctlControl(ctx gvcontext.Context, tsk *kernel.Task, cmd uint32, arg arch.SyscallArgument) error {
	switch cmd {
	case linux.TIOCSCTTY:
		if t.ktty != nil {
			steal := arg.Int() == 1
			_ = tsk.ThreadGroup().SetControllingTTY(ctx, t.ktty, steal, true)
		}
		return nil
	case linux.TIOCNOTTY:
		if t.ktty != nil {
			_ = tsk.ThreadGroup().ReleaseControllingTTY(ctx, t.ktty)
		}
		return nil
	case linux.TIOCGPTN:
		ret := primitive.Uint32(0)
		_, err := ret.CopyOut(tsk, arg.Pointer())
		return err
	case linux.FIONREAD:
		ret := primitive.Int32(t.readableBytes())
		_, err := ret.CopyOut(tsk, arg.Pointer())
		return err
	default:
		switch arg.Uint() {
		case linux.TCIFLUSH, linux.TCIOFLUSH:
			t.flushInput()
		case linux.TCOFLUSH:
		default:
			return linuxerr.EINVAL
		}
		return nil
	}
}

// setupKernelStdio initializes guest terminal state or stdin pump, binds
// descriptors 0..2 into fdTable, and returns the created ttyState and cleanup.
func (s *Sandbox) setupKernelStdio(ctx context.Context, sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, fdTable *kernel.FDTable) (*ttyState, func(), error) {
	var cleanups []func()
	runCleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	var tty *ttyState
	if s.cfg.TTY || isHostTerminalReader(s.cfg.Stdin) {
		restoreTerm, rawHost := enterHostRawMode(s.cfg.Stdin, s.cfg.Stdout)
		cleanups = append(cleanups, restoreTerm)
		rows, cols, _ := hostTerminalSize(s.cfg.Stdin, s.cfg.Stdout)
		tty = newTTYState(s.cfg.Stdin, s.cfg.Stdout, rawHost, rows, cols)
		stopWinch := watchHostWinch(ctx, s.cfg.Stdin, s.cfg.Stdout, func(r, c uint16) {
			tty.setWinsize(linux.Winsize{Row: r, Col: c})
		})
		cleanups = append(cleanups, stopWinch, tty.stop)
	}

	var pump *stdinPump
	if s.cfg.Stdin != nil && tty == nil {
		pump = newStdinPump(s.cfg.Stdin)
		cleanups = append(cleanups, pump.stop)
	}

	stdio, err := openStdioFDs(sctx, vfsObj, creds, s.cfg.Stdin, s.cfg.Stdout, s.cfg.Stderr, tty, pump)
	if err != nil {
		runCleanup()
		return nil, nil, err
	}
	_, fdErr := fdTable.NewFDs(sctx, 0, stdio[:], kernel.FDFlags{})
	for _, fd := range stdio {
		fd.DecRef(sctx)
	}
	if fdErr != nil {
		runCleanup()
		return nil, nil, fmt.Errorf("gvx: bind stdio FDs: %w", fdErr)
	}
	return tty, runCleanup, nil
}

// activateRestoredStdio rebinds host terminal mode, window resize watchers,
// and input pumps for a restored kernel and returns a cleanup callback.
func (s *Sandbox) activateRestoredStdio(ctx context.Context, tg *kernel.ThreadGroup, collector *restoreStdioCollector) func() {
	var restoredTTYs []*ttyState
	var restoredPumps []*stdinPump
	if collector != nil {
		collector.mu.Lock()
		restoredTTYs = append(restoredTTYs, collector.ttys...)
		restoredPumps = append(restoredPumps, collector.pumps...)
		collector.mu.Unlock()
	}
	if ktty := tg.TTY(); ktty != nil {
		if ts, ok := ktty.TTYOperations.(*ttyState); ok && ts != nil {
			found := false
			for _, existing := range restoredTTYs {
				if existing == ts {
					found = true
					break
				}
			}
			if !found {
				restoredTTYs = append(restoredTTYs, ts)
			}
		}
	}

	var cleanups []func()
	if s.cfg.TTY || isHostTerminalReader(s.cfg.Stdin) {
		restoreTerm, _ := enterHostRawMode(s.cfg.Stdin, s.cfg.Stdout)
		cleanups = append(cleanups, restoreTerm)
		if len(restoredTTYs) > 0 {
			stopWinch := watchHostWinch(ctx, s.cfg.Stdin, s.cfg.Stdout, func(r, c uint16) {
				for _, ts := range restoredTTYs {
					ts.setWinsize(linux.Winsize{Row: r, Col: c})
				}
			})
			cleanups = append(cleanups, stopWinch)
		}
	}
	for _, ts := range restoredTTYs {
		ts.ActivateRestoredTTY()
		cleanups = append(cleanups, ts.stop)
	}
	for _, p := range restoredPumps {
		cleanups = append(cleanups, p.stop)
	}
	return func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
}
