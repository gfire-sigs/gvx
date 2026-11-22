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

package netbackend

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	policyMaxItems      = 1024
	policyStreamChunk   = 32 << 10
	policyReadCoalesce  = time.Millisecond
	policyWriteTimeout  = 100 * time.Millisecond
	policyCreditPerByte = 8 * uint64(time.Second) // bit-nanoseconds per byte
	// Each active direction can read one byte before reserving queue space.
	policyMaxStreams = maxNATTCPRelays
)

var (
	errPolicyHandoffPaused = errors.New("netbackend: policy handoff paused")
	policyStreamBuffers    = sync.Pool{New: func() any { return new([policyStreamChunk]byte) }}
)

type policyBucket struct {
	limit  PolicyLimit
	credit uint64
	last   time.Time
}

func policyByteCredit(n int) uint64 { return uint64(n) * policyCreditPerByte }

func policyCreditWait(credit, rate uint64) time.Duration {
	return time.Duration(1 + (credit-1)/rate) // ceil(credit/rate), for positive credit
}

func (b *policyBucket) refill(now time.Time) {
	elapsed := now.Sub(b.last)
	if elapsed <= 0 || b.limit.RateBPS == 0 {
		return
	}
	b.last = now
	remaining := policyByteCredit(b.limit.BurstBytes) - b.credit
	// Compare before multiplying: elapsed nanoseconds times rate can overflow.
	if remaining == 0 || elapsed >= policyCreditWait(remaining, b.limit.RateBPS) {
		b.credit += remaining
		return
	}
	b.credit += uint64(elapsed) * b.limit.RateBPS
}

func (b *policyBucket) replace(limit PolicyLimit, freeze time.Time) {
	b.refill(freeze)
	b.limit = limit
	b.credit = min(b.credit, policyByteCredit(limit.BurstBytes))
}

func (b *policyBucket) acquire(n int, now time.Time) time.Duration {
	if n == 0 || b.limit.RateBPS == 0 {
		return 0
	}
	b.refill(now)
	cost := policyByteCredit(n)
	if cost > b.credit {
		return policyCreditWait(cost-b.credit, b.limit.RateBPS)
	}
	b.credit -= cost
	return 0
}

func (b *policyBucket) complete(n, written int, now time.Time) {
	if n == 0 || b.limit.RateBPS == 0 {
		return
	}
	b.credit += policyByteCredit(n - written)
	// A bounded write can submit bytes anywhere in its time window. Do not
	// refill during that window: a stalled write cannot accumulate a burst.
	b.last = now
}

type policyWork struct {
	prev, next *policyWork
	queued     bool
	n          int
	chain      PolicyChain
	tuples     []PolicyTuple
	inline     [2]PolicyTuple // NAT and publication each use at most two legs
	ctx        context.Context
	stream     bool // capacity belongs to the staged chunk, not each write attempt
	send       func() (int, error)
	dispose    func()
	done       chan error
}

func (w *policyWork) finish(err error) {
	if w.dispose != nil {
		w.dispose()
	}
	if w.done != nil {
		w.done <- err
	}
}

func finishPolicyWork(head *policyWork, err error) {
	for w := head; w != nil; {
		next := w.next
		w.next = nil
		w.finish(err)
		w = next
	}
}

type policyScheduler struct {
	mu          sync.Mutex
	bucket      policyBucket
	bytes       int
	items       int
	head, tail  *policyWork
	streamBytes int
	pending     map[*policyStream]struct{}
	wake        chan struct{}
	space       chan struct{} // closes when capacity changes, if a stream waits
}

func (s *policyScheduler) init(limit PolicyLimit, now time.Time) {
	s.bucket = policyBucket{limit: limit, last: now}
	s.wake = make(chan struct{}, 1)
}

func (s *policyScheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *policyScheduler) signalSpace() {
	if s.space != nil {
		close(s.space)
		s.space = nil
	}
}

func policyQueueLimits(limit PolicyLimit) (maxUnit, maxBytes int) {
	if limit.RateBPS == 0 {
		return maxPolicyQueue, maxPolicyQueue
	}
	return limit.BurstBytes, limit.QueueBytes
}

func (s *policyScheduler) append(w *policyWork) {
	w.prev, w.next, w.queued = s.tail, nil, true
	if s.tail == nil {
		s.head = w
	} else {
		s.tail.next = w
	}
	s.tail = w
	if !w.stream {
		s.items++
		s.bytes += w.n
	}
}

func (s *policyScheduler) unlink(w *policyWork) {
	if w.prev == nil {
		s.head = w.next
	} else {
		w.prev.next = w.next
	}
	if w.next == nil {
		s.tail = w.prev
	} else {
		w.next.prev = w.prev
	}
	w.prev, w.next, w.queued = nil, nil, false
}

func (s *policyScheduler) uncharge(w *policyWork) {
	if w.stream {
		return
	}
	s.items--
	s.bytes -= w.n
	s.signalSpace()
}

func (s *policyScheduler) cancel(w *policyWork) bool {
	s.mu.Lock()
	if !w.queued {
		s.mu.Unlock()
		return false
	}
	s.unlink(w)
	s.uncharge(w)
	s.mu.Unlock()
	s.signal()
	return true
}

func (s *policyScheduler) replace(active *CompiledPolicy, limit PolicyLimit, freeze time.Time) *policyWork {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bucket.replace(limit, freeze)
	maxUnit, maxBytes := policyQueueLimits(limit)
	kept := min(s.streamBytes, maxBytes)
	if s.streamBytes > maxBytes {
		for stream := range s.pending {
			stream.cancel(ErrPolicyQueueFull)
		}
	}
	var rejected *policyWork
	for w := s.head; w != nil; {
		next := w.next
		overCapacity := !w.stream && (w.n > maxUnit || w.n > maxBytes-kept)
		if overCapacity || (w.stream && context.Cause(w.ctx) != nil) || !active.allows(w.chain, w.tuples) {
			s.unlink(w)
			s.uncharge(w)
			w.next = rejected
			rejected = w
		} else if !w.stream {
			kept += w.n
		}
		w = next
	}
	s.signalSpace()
	return rejected
}

func (s *policyScheduler) drain() {
	s.mu.Lock()
	head := s.head
	for w := head; w != nil; w = w.next {
		w.queued = false
		w.prev = nil
	}
	s.head, s.tail, s.items, s.bytes = nil, nil, 0, 0
	s.signalSpace()
	s.mu.Unlock()
	finishPolicyWork(head, ErrPolicyDenied)
}

func (s *policyScheduler) run(p *NATPolicy) {
	defer s.drain()
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-p.done:
			return
		default:
		}
		wait := s.dispatch(p)
		if wait == 0 {
			continue
		}
		var tick <-chan time.Time
		if wait > 0 {
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				timer.Reset(wait)
			}
			tick = timer.C
		}
		select {
		case <-p.done:
			return
		case <-s.wake:
			if tick != nil {
				timer.Stop()
			}
		case <-tick:
		}
	}
}

// dispatch returns zero after removing work, or a negative duration when idle.
func (s *policyScheduler) dispatch(p *NATPolicy) time.Duration {
	release := p.tryRead()
	if release == nil {
		return -1
	}
	if p.active == nil {
		release()
		return -1
	}
	s.mu.Lock()
	w := s.head
	if w == nil {
		s.mu.Unlock()
		release()
		return -1
	}
	var canceled error
	if w.ctx != nil {
		canceled = context.Cause(w.ctx)
	}
	if canceled == nil {
		now := time.Now()
		// A worker can pin the rules before cutover and acquire s.mu after it starts.
		if p.transition.Load() != nil {
			s.mu.Unlock()
			release()
			return -1
		}
		if wait := s.bucket.acquire(w.n, now); wait > 0 {
			s.mu.Unlock()
			release()
			return wait
		}
	}
	s.unlink(w)
	s.mu.Unlock()
	var written int
	result := canceled
	if canceled == nil {
		written, result = w.send()
	}
	s.mu.Lock()
	if canceled == nil {
		s.bucket.complete(w.n, written, time.Now())
	}
	s.uncharge(w)
	s.mu.Unlock()
	release()
	w.finish(result)
	return 0
}

func (p *NATPolicy) scheduler(chain PolicyChain) *policyScheduler {
	if chain == PolicyOutput {
		return &p.rx
	}
	// Routed packets enter on the trusted guest attachment, like INPUT.
	return &p.tx
}

func (p *NATPolicy) reserveStream(ctx context.Context, stream *policyStream, want int) (int, error) {
	s := p.scheduler(stream.chain)
	for {
		release, err := p.readStreamGate(ctx)
		if err != nil {
			return 0, err
		}
		s.mu.Lock()
		_, maxBytes := policyQueueLimits(s.bucket.limit)
		room := maxBytes - s.bytes - s.streamBytes
		if room > 0 && s.items+len(s.pending) < policyMaxItems {
			n := want
			if n > room {
				n = 1 // Forward the readiness byte without allocating a chunk.
			}
			if s.pending == nil {
				s.pending = make(map[*policyStream]struct{})
			}
			s.pending[stream] = struct{}{}
			s.streamBytes += n
			s.mu.Unlock()
			release()
			return n, nil
		}
		if s.space == nil {
			s.space = make(chan struct{})
		}
		space := s.space
		s.mu.Unlock()
		release()
		select {
		case <-space:
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		}
	}
}

func (s *policyScheduler) releaseStream(stream *policyStream, n int) {
	s.mu.Lock()
	delete(s.pending, stream)
	s.streamBytes -= n
	s.signalSpace()
	s.mu.Unlock()
}

func (s *policyScheduler) trimStream(n int) {
	s.mu.Lock()
	s.streamBytes -= n
	s.signalSpace()
	s.mu.Unlock()
}

func (p *NATPolicy) submit(w *policyWork) error {
	var release func()
	if w.stream {
		var err error
		release, err = p.readStreamGate(w.ctx)
		if err != nil {
			return err
		}
	} else {
		release = p.tryRead()
		if release == nil {
			return ErrPolicyDenied
		}
	}
	if !p.active.allows(w.chain, w.tuples) {
		release()
		return ErrPolicyDenied
	}
	if w.ctx != nil {
		if err := context.Cause(w.ctx); err != nil {
			release()
			return err
		}
	}
	s := p.scheduler(w.chain)
	s.mu.Lock()
	maxUnit, maxBytes := policyQueueLimits(s.bucket.limit)
	fits := w.n >= 0 && w.n <= maxUnit &&
		w.n <= maxBytes-s.bytes-s.streamBytes && s.items+len(s.pending) < policyMaxItems
	if !w.stream && !fits {
		s.mu.Unlock()
		release()
		return ErrPolicyQueueFull
	}
	s.append(w)
	s.mu.Unlock()
	release()
	s.signal()
	return nil
}

// Enqueue admits one whole unit without waiting for the gate, tokens, or I/O.
// Enqueue owns dispose on success and rejection. Send and dispose must finish
// in bounded time and must not wait for a synchronous policy operation.
func (p *NATPolicy) Enqueue(chain PolicyChain, n int, send func(), dispose func(), tuples ...PolicyTuple) bool {
	if p == nil {
		send()
		if dispose != nil {
			dispose()
		}
		return true
	}
	w := &policyWork{n: n, chain: chain, dispose: dispose, send: func() (int, error) {
		send()
		return n, nil
	}}
	if len(tuples) <= len(w.inline) {
		w.tuples = w.inline[:copy(w.inline[:], tuples)]
	} else {
		w.tuples = slices.Clone(tuples)
	}
	if err := p.submit(w); err != nil {
		w.finish(err)
		return false
	}
	return true
}

// Send waits for a whole unit to reach its destination or return an error.
// Send pins the active rule snapshot. Bound socket writes with a write deadline.
func (p *NATPolicy) Send(ctx context.Context, chain PolicyChain, n int, send func() error, tuples ...PolicyTuple) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if p == nil {
		return send()
	}
	w := &policyWork{n: n, chain: chain, tuples: tuples, ctx: ctx, done: make(chan error, 1), send: func() (int, error) {
		// A callback error cannot distinguish partial I/O from no handoff.
		return n, send()
	}}
	return p.sendWork(w)
}

func (p *NATPolicy) sendWork(w *policyWork) error {
	if err := p.submit(w); err != nil {
		return err
	}
	select {
	case err := <-w.done:
		return err
	case <-w.ctx.Done():
		if p.scheduler(w.chain).cancel(w) {
			return context.Cause(w.ctx)
		}
		// A dispatched callback can still own the caller's payload buffer.
		return <-w.done
	}
}

type policyStream struct {
	chain  PolicyChain
	tuples []PolicyTuple
	cancel context.CancelCauseFunc
}

func (p *NATPolicy) readStreamGate(ctx context.Context) (func(), error) {
	if p.release == nil {
		return nil, ErrPolicyDenied
	}
	for {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		transition := p.transition.Load()
		if transition == nil {
			if release := p.tryRead(); release != nil {
				return release, nil
			}
			continue
		}
		select {
		case <-p.done:
			return nil, ErrPolicyDenied
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-transition.published:
		}
	}
}

// CopyStream copies one direction and stops reading while a chunk awaits
// capacity. The caller owns both connections and any half-close on EOF.
// CopyStream owns src's read deadline and dst's write deadline during the copy.
func (p *NATPolicy) CopyStream(ctx context.Context, chain PolicyChain, dst, src net.Conn, tuples ...PolicyTuple) error {
	if p == nil {
		_, err := io.Copy(dst, src)
		return err
	}
	release, err := p.readStreamGate(ctx)
	if err != nil {
		return err
	}
	if !p.active.allows(chain, tuples) {
		release()
		return ErrPolicyDenied
	}
	dir := 0
	if chain == PolicyOutput {
		dir = 1
	}
	p.streamsMu.Lock()
	if p.streamCounts[dir] >= policyMaxStreams {
		p.streamsMu.Unlock()
		release()
		return ErrPolicyQueueFull
	}
	ctx, cancel := context.WithCancelCause(ctx)
	stream := &policyStream{chain: chain, tuples: tuples, cancel: cancel}
	if p.streams == nil {
		p.streams = make(map[*policyStream]struct{})
	}
	p.streams[stream] = struct{}{}
	p.streamCounts[dir]++
	p.streamsMu.Unlock()
	release()
	defer func() {
		p.streamsMu.Lock()
		delete(p.streams, stream)
		p.streamCounts[dir]--
		p.streamsMu.Unlock()
		cancel(nil)
	}()
	readInterrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = src.SetReadDeadline(time.Now())
		close(readInterrupted)
	})
	defer func() {
		if !stop() {
			<-readInterrupted
		}
	}()

	var ready [1]byte
	var chunk []byte
	var written int
	work := policyWork{chain: chain, tuples: tuples, ctx: ctx, stream: true, done: make(chan error, 1), send: func() (int, error) {
		err := policyWrite(dst, func() error {
			var err error
			written, err = dst.Write(chunk)
			if err == nil && written != len(chunk) {
				return io.ErrShortWrite
			}
			return err
		})
		return written, err
	}}
	relayChunk := func(readErr error) (error, error) {
		want := 1
		if readErr == nil {
			want = policyStreamChunk
		}
		reserved, err := p.reserveStream(ctx, stream, want)
		if err != nil {
			return nil, err
		}
		s := p.scheduler(chain)
		var buf *[policyStreamChunk]byte
		defer func() {
			chunk = nil
			if buf != nil {
				policyStreamBuffers.Put(buf)
			}
			s.releaseStream(stream, reserved)
		}()
		chunk = ready[:]
		if reserved > 1 {
			buf = policyStreamBuffers.Get().(*[policyStreamChunk]byte)
			buf[0] = ready[0]
			n, err := readPolicyStreamTail(ctx, src, buf[1:reserved])
			chunk = buf[:1+n]
			readErr = err
		}
		if unused := reserved - len(chunk); unused > 0 {
			s.trimStream(unused)
			reserved -= unused
		}
		for len(chunk) != 0 {
			work.n = len(chunk)
			written = 0
			err := p.sendWork(&work)
			if cause := context.Cause(ctx); cause != nil {
				return nil, cause
			}
			chunk = chunk[written:]
			if errors.Is(err, errPolicyHandoffPaused) {
				waiter, ok := dst.(interface{ waitPolicyWrite(context.Context) error })
				if !ok {
					return nil, err
				}
				if err := waiter.waitPolicyWrite(ctx); err != nil {
					return nil, err
				}
			} else if err != nil && !isTimeout(err) {
				return nil, err
			}
		}
		return readErr, nil
	}
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		n, readErr := src.Read(ready[:])
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if n != 0 {
			var writeErr error
			readErr, writeErr = relayChunk(readErr)
			if writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

// After readiness, bound the extra read so idle sockets cannot pin queue space.
func readPolicyStreamTail(ctx context.Context, src net.Conn, buf []byte) (int, error) {
	if err := src.SetReadDeadline(time.Now().Add(policyReadCoalesce)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return src.Read(buf)
		}
		return 0, err
	}
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	n, err := src.Read(buf)
	if isTimeout(err) {
		err = nil
	}
	if resetErr := src.SetReadDeadline(time.Time{}); resetErr != nil && !errors.Is(resetErr, io.ErrClosedPipe) {
		return n, errors.Join(err, resetErr)
	}
	return n, err
}

// policyWrite bounds the socket operation while the worker pins the rules.
// The caller must own the socket's write deadline for the duration of send.
func policyWrite(conn interface{ SetWriteDeadline(time.Time) error }, send func() error) error {
	if err := conn.SetWriteDeadline(time.Now().Add(policyWriteTimeout)); err != nil {
		return err
	}
	err := send()
	if resetErr := conn.SetWriteDeadline(time.Time{}); resetErr != nil {
		return errors.Join(err, resetErr)
	}
	return err
}
