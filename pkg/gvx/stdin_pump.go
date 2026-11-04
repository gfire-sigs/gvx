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
	"io"
	"sync"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// maxStdinChunk is the largest host read that one pending guest read starts.
const maxStdinChunk = 64 * 1024

// stdinPump lets a guest read a host io.Reader without blocking the task
// goroutine. A host read cannot be interrupted, so a task that called it
// directly ignored SIGKILL until the host reader returned. The pump runs the
// host read in a helper goroutine. A guest read that finds no data returns
// ErrWouldBlock, and the read system call waits on the queue of the pump. The
// wait ends on a signal, as on Linux.
//
// At most one host read runs at a time. The pump reads only when a guest read
// or a poll waits for input, so the guest never loses data to a read-ahead
// beyond one chunk. The helper goroutine ends when the host reader returns.
type stdinPump struct {
	r  io.Reader
	wq waiter.Queue

	mu sync.Mutex
	// buf holds the bytes that the host read returned and the guest did not
	// read yet.
	buf []byte
	// err is the error that ended the host reader. It stays set, so every
	// later read returns it after the buffer is empty.
	err error
	// pending is set while a helper goroutine reads the host reader.
	pending bool
}

func newStdinPump(r io.Reader) *stdinPump { return &stdinPump{r: r} }

// read implements the non-blocking read of the guest. It returns ErrWouldBlock
// while no data and no error is available.
func (p *stdinPump) read(ctx context.Context, dst usermem.IOSequence) (int64, error) {
	if dst.NumBytes() == 0 {
		return 0, nil
	}
	p.mu.Lock()
	if len(p.buf) > 0 {
		n := min(int(dst.NumBytes()), len(p.buf))
		chunk := append([]byte(nil), p.buf[:n]...)
		p.buf = p.buf[n:]
		p.mu.Unlock()
		copied, err := dst.CopyOut(ctx, chunk)
		return int64(copied), err
	}
	if p.err != nil {
		err := p.err
		p.mu.Unlock()
		return 0, err
	}
	p.startReadLocked(int(min(dst.NumBytes(), maxStdinChunk)))
	p.mu.Unlock()
	return 0, linuxerr.ErrWouldBlock
}

// startReadLocked starts a helper goroutine unless one runs already.
func (p *stdinPump) startReadLocked(size int) {
	if p.pending {
		return
	}
	p.pending = true
	go func() {
		buf := make([]byte, size)
		n, err := p.r.Read(buf)
		p.mu.Lock()
		p.buf = append(p.buf, buf[:n]...)
		if err != nil {
			p.err = err
		}
		p.pending = false
		p.mu.Unlock()
		p.wq.Notify(waiter.ReadableEvents)
	}()
}

// readiness reports whether a read returns without blocking.
func (p *stdinPump) readiness() waiter.EventMask {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) > 0 || p.err != nil {
		return waiter.ReadableEvents
	}
	return 0
}

// register adds a waiter, and it starts a host read so that a poll sees the
// input although no guest read runs.
func (p *stdinPump) register(e *waiter.Entry) {
	p.wq.EventRegister(e)
	p.mu.Lock()
	if len(p.buf) == 0 && p.err == nil {
		p.startReadLocked(4096)
	}
	p.mu.Unlock()
}
