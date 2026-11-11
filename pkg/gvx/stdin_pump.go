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
	"time"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// maxStdinChunk is the largest host read that one pending guest read starts.
const maxStdinChunk = 64 * 1024

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

func newStdinPump(r io.Reader) *stdinPump {
	p := &stdinPump{r: r}
	if r == nil {
		p.err = io.EOF
	}
	return p
}

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
		if copied < len(chunk) {
			// Bytes that did not reach the guest stay unread, as in a pipe.
			p.mu.Lock()
			p.buf = append(chunk[copied:len(chunk):len(chunk)], p.buf...)
			p.mu.Unlock()
		}
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

// startReadLocked starts a helper goroutine unless one runs already or the pump stopped.
func (p *stdinPump) startReadLocked(size int) {
	if p.pending || p.stopped {
		return
	}
	if p.r == nil {
		p.err = io.EOF
		return
	}
	r := p.r
	done := make(chan struct{})
	p.pending = true
	p.readDone = done
	go func() {
		defer close(done)
		buf := make([]byte, size)
		n, err := r.Read(buf)
		p.mu.Lock()
		stopped := p.stopped
		if !stopped {
			p.buf = append(p.buf, buf[:n]...)
			if err != nil {
				p.err = err
			}
		}
		p.pending = false
		p.readDone = nil
		if stopped {
			if d, ok := r.(readDeadlineSetter); ok {
				_ = d.SetReadDeadline(time.Time{})
			}
		}
		p.mu.Unlock()
		if stopped {
			p.wq.Notify(waiter.ReadableEvents | waiter.EventHUp)
			return
		}
		p.wq.Notify(waiter.ReadableEvents)
	}()
}

// stop ends the pump when a sandbox run finishes. For a reader that supports
// read deadlines, it expires the read deadline to unblock an in-flight Read and
// resets the deadline once the helper goroutine returns.
func (p *stdinPump) stop() {
	p.mu.Lock()
	alreadyStopped := p.stopped
	p.stopped = true
	if p.err == nil {
		p.err = io.EOF
	}
	done := p.readDone
	r := p.r
	p.mu.Unlock()

	if !alreadyStopped {
		p.wq.Notify(waiter.ReadableEvents | waiter.EventHUp)
	}
	if done == nil {
		return
	}
	select {
	case <-done:
		return
	default:
	}
	if d, ok := r.(readDeadlineSetter); ok {
		if err := d.SetReadDeadline(time.Now()); err == nil {
			select {
			case <-done:
				_ = d.SetReadDeadline(time.Time{})
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}

// readiness reports whether a read returns without blocking.
func (p *stdinPump) readiness() waiter.EventMask {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return waiter.ReadableEvents | waiter.EventHUp
	}
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
	if !p.stopped && len(p.buf) == 0 && p.err == nil {
		p.startReadLocked(4096)
	}
	p.mu.Unlock()
}
