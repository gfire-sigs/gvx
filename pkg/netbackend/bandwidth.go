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
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxBandwidthBPS is the largest supported rate, in bits per second.
	MaxBandwidthBPS = 1_000_000_000_000

	bandwidthMaxUnit       = 256 << 10
	bandwidthQueueBytes    = 4 << 20
	bandwidthQueueItems    = 1024
	bandwidthStreamChunk   = 16 << 10
	bandwidthCreditPerByte = 8 * uint64(time.Second) // bit-nanoseconds per byte
	bandwidthBurstCredit   = bandwidthMaxUnit * bandwidthCreditPerByte
	bandwidthClosedFlag    = 1 << 2
)

var (
	errBandwidthUnit      = errors.New("netbackend: invalid bandwidth unit size")
	errBandwidthQueueFull = errors.New("netbackend: bandwidth datagram queue full")
	bandwidthCopyPool     = sync.Pool{New: func() any { return new([bandwidthStreamChunk]byte) }}
)

// BandwidthRates holds guest-relative rates in bits per second. Zero is unlimited.
type BandwidthRates struct {
	TXBPS, RXBPS uint64
}

// Validate reports whether both rates are supported.
func (r BandwidthRates) Validate() error {
	if r.TXBPS > MaxBandwidthBPS {
		return fmt.Errorf("TX bandwidth %d exceeds %d bits per second", r.TXBPS, MaxBandwidthBPS)
	}
	if r.RXBPS > MaxBandwidthBPS {
		return fmt.Errorf("RX bandwidth %d exceeds %d bits per second", r.RXBPS, MaxBandwidthBPS)
	}
	return nil
}

// BandwidthDirection identifies a direction relative to the guest.
type BandwidthDirection uint8

const (
	// BandwidthTX is guest traffic going toward the host.
	BandwidthTX BandwidthDirection = iota
	// BandwidthRX is host traffic going toward the guest.
	BandwidthRX
)

// BandwidthIdleHold keeps a UDP session live while accepted traffic is delayed
// or in flight. Its zero value is ready to use and must not be copied after use.
type BandwidthIdleHold struct {
	mu      sync.Mutex
	pending int
	idle    chan struct{}
}

// Pending reports whether any handoff is holding the session open.
func (h *BandwidthIdleHold) Pending() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pending != 0
}

// Wait waits until the session has no pending handoffs, or ctx ends.
func (h *BandwidthIdleHold) Wait(ctx context.Context) error {
	h.mu.Lock()
	if h.pending == 0 {
		h.mu.Unlock()
		return context.Cause(ctx)
	}
	if h.idle == nil {
		h.idle = make(chan struct{})
	}
	idle := h.idle
	h.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func changeBandwidthHolds(holds []*BandwidthIdleHold, delta int) {
	for _, h := range holds {
		if h == nil {
			continue
		}
		h.mu.Lock()
		h.pending += delta
		if h.pending == 0 && h.idle != nil {
			close(h.idle)
			h.idle = nil
		}
		h.mu.Unlock()
	}
}

// BandwidthFlow orders asynchronous handoffs within one direction of one
// shaper. Its zero value is ready to use and must not be copied after use.
type BandwidthFlow struct {
	pending atomic.Int32
	running bool // protected by the owning shaper mutex
}

// Pending reports whether a queued or running handoff still owns the flow.
// A sole producer may bypass EnqueueOrdered when Pending and Enabled are both
// false.
func (f *BandwidthFlow) Pending() bool { return f.pending.Load() != 0 }

// BandwidthShaper shares two token buckets across a sandbox's NAT handoffs.
// A nil shaper passes traffic through without limiting it.
type BandwidthShaper struct {
	flags  atomic.Uint32
	mu     sync.Mutex
	queues [2]bandwidthQueue
}

// NewBandwidthShaper constructs a shaper for prevalidated rates. Neither
// direction starts with credit, and workers are only started if work queues.
func NewBandwidthShaper(rates BandwidthRates) *BandwidthShaper {
	s := &BandwidthShaper{}
	s.SetRates(rates)
	return s
}

// Rates returns the installed pair atomically.
func (s *BandwidthShaper) Rates() BandwidthRates {
	if s == nil {
		return BandwidthRates{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return BandwidthRates{TXBPS: s.queues[BandwidthTX].rate, RXBPS: s.queues[BandwidthRX].rate}
}

// SetRates replaces both prevalidated rates atomically. Queued traffic uses
// the new rates; reservations already handed off are not revoked.
func (s *BandwidthShaper) SetRates(rates BandwidthRates) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.flags.Load()&bandwidthClosedFlag != 0 ||
		(rates.TXBPS == s.queues[BandwidthTX].rate && rates.RXBPS == s.queues[BandwidthRX].rate) {
		return
	}
	now := time.Now()
	s.queues[BandwidthTX].setRate(rates.TXBPS, now)
	s.queues[BandwidthRX].setRate(rates.RXBPS, now)
	var flags uint32
	if rates.TXBPS != 0 {
		flags |= 1 << BandwidthTX
	}
	if rates.RXBPS != 0 {
		flags |= 1 << BandwidthRX
	}
	s.flags.Store(flags)
}

// Enabled reports whether the direction needs the shaper's handoff path,
// including after Close when that path rejects new work.
func (s *BandwidthShaper) Enabled(dir BandwidthDirection) bool {
	return s != nil && s.flags.Load()&(bandwidthClosedFlag|1<<dir) != 0
}

// Shape waits for a reservation, then runs write in the caller's goroutine.
// Cancellation or Close ends a queued wait; the caller owns any interruption
// of write after handoff. The result reports bytes actually handed off.
func (s *BandwidthShaper) Shape(ctx context.Context, dir BandwidthDirection, n int, write func() (int, error), holds ...*BandwidthIdleHold) (int, error) {
	return s.shape(ctx, dir, n, write, holds, true)
}

// ShapeDatagram waits for a whole datagram reservation, then writes in the
// caller's goroutine. A full queue rejects the datagram without waiting.
func (s *BandwidthShaper) ShapeDatagram(ctx context.Context, dir BandwidthDirection, n int, write func() (int, error), holds ...*BandwidthIdleHold) (int, error) {
	return s.shape(ctx, dir, n, write, holds, false)
}

func (s *BandwidthShaper) shape(ctx context.Context, dir BandwidthDirection, n int, write func() (int, error), holds []*BandwidthIdleHold, waitForSpace bool) (int, error) {
	if s != nil && (n < 0 || n > bandwidthMaxUnit) {
		return 0, errBandwidthUnit
	}
	if len(holds) != 0 {
		changeBandwidthHolds(holds, 1)
		defer changeBandwidthHolds(holds, -1)
	}
	// A disabled direction admits the handoff at the flags load.
	if !s.Enabled(dir) {
		return s.write(ctx, dir, n, bandwidthReservation{}, write)
	}
	reservation, err := s.acquire(ctx, dir, n, waitForSpace)
	if err != nil {
		return 0, err
	}
	return s.write(ctx, dir, n, reservation, write)
}

// Copy copies a stream in chunks so established relays see live rate changes.
// The caller owns src and dst, including interruption of a blocked Read or Write.
func (s *BandwidthShaper) Copy(ctx context.Context, dir BandwidthDirection, dst io.Writer, src io.Reader) (int64, error) {
	if s == nil {
		return io.Copy(dst, src)
	}
	buf := bandwidthCopyPool.Get().(*[bandwidthStreamChunk]byte)
	defer bandwidthCopyPool.Put(buf)
	var total int64
	for {
		if err := context.Cause(ctx); err != nil {
			return total, err
		}
		n, readErr := src.Read(buf[:])
		if n > 0 {
			written, err := s.Shape(ctx, dir, n, func() (int, error) {
				return dst.Write(buf[:n])
			})
			if written < 0 || written > n {
				written = 0
			}
			total += int64(written)
			if err != nil {
				return total, err
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// Enqueue admits a whole unit without waiting for tokens or queue capacity.
// It owns release even on rejection. For an unlimited direction, it invokes
// send and release inline; for a limited direction, it dispatches each
// accepted send independently. Holds stay active through release. Callbacks
// must finish in bounded time.
func (s *BandwidthShaper) Enqueue(ctx context.Context, dir BandwidthDirection, n int, send func() (int, error), release func(), holds ...*BandwidthIdleHold) bool {
	return s.EnqueueOrdered(ctx, dir, nil, n, send, release, holds...)
}

// EnqueueOrdered works like Enqueue but serializes sends within flow. A later
// send cannot overtake an earlier send or its release, even when the rate is
// cleared. Canceled and rejected units are released without sending.
func (s *BandwidthShaper) EnqueueOrdered(ctx context.Context, dir BandwidthDirection, flow *BandwidthFlow, n int, send func() (int, error), release func(), holds ...*BandwidthIdleHold) bool {
	if n > bandwidthMaxUnit {
		releaseBandwidthWork(release)
		return false
	}
	return s.enqueue(ctx, dir, flow, n, n, send, release, holds)
}

// EnqueuePacket bounds the queue by retainedBytes but paces the packet by
// wireBytes. A reassembled packet can spend several bursts of credit before
// one handoff. Send reports wireBytes on success and zero otherwise. Only the
// last quantum is eligible for a refund if the handoff fails.
func (s *BandwidthShaper) EnqueuePacket(ctx context.Context, dir BandwidthDirection, retainedBytes, wireBytes int, send func() (int, error), release func()) bool {
	return s.enqueue(ctx, dir, nil, retainedBytes, wireBytes, send, release, nil)
}

func (s *BandwidthShaper) enqueue(ctx context.Context, dir BandwidthDirection, flow *BandwidthFlow, retainedBytes, wireBytes int, send func() (int, error), release func(), holds []*BandwidthIdleHold) bool {
	if context.Cause(ctx) != nil || retainedBytes < 0 || wireBytes < 0 {
		releaseBandwidthWork(release)
		return false
	}
	if s == nil || (flow == nil && !s.Enabled(dir)) {
		return enqueueBandwidthInline(ctx, send, release, holds)
	}
	s.mu.Lock()
	q := &s.queues[dir]
	if s.flags.Load()&bandwidthClosedFlag != 0 {
		s.mu.Unlock()
		releaseBandwidthWork(release)
		return false
	}
	if q.rate == 0 && flow == nil {
		s.mu.Unlock()
		return enqueueBandwidthInline(ctx, send, release, holds)
	}
	if !q.fits(retainedBytes) {
		s.mu.Unlock()
		releaseBandwidthWork(release)
		return false
	}
	w := &bandwidthWork{
		n: retainedBytes, wireBytes: wireBytes, remaining: wireBytes,
		ctx: ctx, flow: flow, send: send, release: release, holds: holds,
	}
	if flow != nil {
		flow.pending.Add(1)
	}
	changeBandwidthHolds(holds, 1)
	q.append(w)
	if ctx.Done() != nil {
		w.stop = context.AfterFunc(ctx, func() { s.cancelAsync(dir, w) })
	}
	s.wake(dir)
	s.mu.Unlock()
	return true
}

func enqueueBandwidthInline(ctx context.Context, send func() (int, error), release func(), holds []*BandwidthIdleHold) bool {
	changeBandwidthHolds(holds, 1)
	if context.Cause(ctx) == nil {
		_, _ = send()
	}
	releaseBandwidthWork(release)
	changeBandwidthHolds(holds, -1)
	return true
}

// Close rejects new work, cancels all queued work, and stops the scheduling
// workers. Already dispatched callbacks keep ownership until they return.
func (s *BandwidthShaper) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	flags := s.flags.Load()
	if flags&bandwidthClosedFlag != 0 {
		s.mu.Unlock()
		return
	}
	s.flags.Store(flags | bandwidthClosedFlag)
	var abandoned [2]*bandwidthWork
	var stopped [2]<-chan struct{}
	for dir := range s.queues {
		q := &s.queues[dir]
		for q.head != nil {
			w := q.head
			q.unlink(w)
			if w.ready != nil {
				w.err = net.ErrClosed
				q.free(w.n)
				close(w.ready)
				continue
			}
			if w.stop != nil {
				w.stop()
			}
			w.next = abandoned[dir]
			abandoned[dir] = w
		}
		q.signalSpace()
		q.signalWorker()
		stopped[dir] = q.stopped
	}
	s.mu.Unlock()
	for dir, head := range abandoned {
		for w := head; w != nil; w = w.next {
			s.finishAsync(BandwidthDirection(dir), w, false)
		}
		if stopped[dir] != nil {
			<-stopped[dir]
		}
	}
}

func (s *BandwidthShaper) acquire(ctx context.Context, dir BandwidthDirection, n int, waitForSpace bool) (bandwidthReservation, error) {
	q := &s.queues[dir]
	for {
		if err := context.Cause(ctx); err != nil {
			return bandwidthReservation{}, err
		}
		s.mu.Lock()
		if s.flags.Load()&bandwidthClosedFlag != 0 {
			s.mu.Unlock()
			return bandwidthReservation{}, net.ErrClosed
		}
		if q.rate == 0 {
			s.mu.Unlock()
			return bandwidthReservation{}, nil
		}
		if q.firstReady() == nil {
			if reservation, wait := q.take(n); wait == 0 {
				s.mu.Unlock()
				return reservation, nil
			}
		}
		if q.fits(n) {
			w := &bandwidthWork{n: n, wireBytes: n, remaining: n, ready: make(chan struct{})}
			q.append(w)
			s.wake(dir)
			s.mu.Unlock()
			return s.wait(ctx, dir, w)
		}
		if !waitForSpace {
			s.mu.Unlock()
			return bandwidthReservation{}, errBandwidthQueueFull
		}
		if q.space == nil {
			q.space = make(chan struct{})
		}
		space := q.space
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return bandwidthReservation{}, context.Cause(ctx)
		case <-space:
		}
	}
}

func (s *BandwidthShaper) wait(ctx context.Context, dir BandwidthDirection, w *bandwidthWork) (bandwidthReservation, error) {
	select {
	case <-w.ready:
		return w.reservation, w.err
	case <-ctx.Done():
		if s.unlink(dir, w) {
			return bandwidthReservation{}, context.Cause(ctx)
		}
		// If dispatch won, return the reservation so write can refund it.
		<-w.ready
		return w.reservation, w.err
	}
}

func (s *BandwidthShaper) unlink(dir BandwidthDirection, w *bandwidthWork) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !w.queued {
		return false
	}
	q := &s.queues[dir]
	q.unlink(w)
	if w.ready != nil {
		q.free(w.n)
	}
	q.signalWorker()
	return true
}

func (s *BandwidthShaper) cancelAsync(dir BandwidthDirection, w *bandwidthWork) {
	if s.unlink(dir, w) {
		s.finishAsync(dir, w, false)
	}
}

func (s *BandwidthShaper) finishAsync(dir BandwidthDirection, w *bandwidthWork, dispatched bool) {
	releaseBandwidthWork(w.release)
	changeBandwidthHolds(w.holds, -1)
	s.mu.Lock()
	q := &s.queues[dir]
	if w.flow != nil {
		if dispatched {
			w.flow.running = false
			q.signalWorker()
		}
		w.flow.pending.Add(-1)
	}
	q.free(w.n)
	s.mu.Unlock()
}

func releaseBandwidthWork(release func()) {
	if release != nil {
		release()
	}
}

func (s *BandwidthShaper) write(ctx context.Context, dir BandwidthDirection, n int, reservation bandwidthReservation, send func() (int, error)) (int, error) {
	var written int
	err := context.Cause(ctx)
	if err == nil {
		written, err = send()
	}
	if reservation.epoch != 0 && written < n {
		s.mu.Lock()
		q := &s.queues[dir]
		if s.flags.Load()&bandwidthClosedFlag == 0 {
			q.refund(reservation, bandwidthCost(n-max(0, written)))
		}
		s.mu.Unlock()
	}
	return written, err
}

// wake starts the direction's worker on its first queued handoff. s.mu is held.
func (s *BandwidthShaper) wake(dir BandwidthDirection) {
	q := &s.queues[dir]
	if q.wake == nil {
		q.wake = make(chan struct{}, 1)
		q.stopped = make(chan struct{})
		go s.run(dir, q)
		return
	}
	q.signalWorker()
}

func (s *BandwidthShaper) run(dir BandwidthDirection, q *bandwidthQueue) {
	defer close(q.stopped)
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		s.mu.Lock()
		if s.flags.Load()&bandwidthClosedFlag != 0 {
			s.mu.Unlock()
			return
		}
		w := q.firstReady()
		var wait time.Duration
		if w != nil {
			cost := w.remaining
			if cost > bandwidthMaxUnit && q.rate != 0 {
				cost = bandwidthMaxUnit
			}
			var reservation bandwidthReservation
			reservation, wait = q.take(cost)
			if wait == 0 {
				if cost < w.remaining {
					w.remaining -= cost
					// Other queued units can use the bucket between quanta.
					if w != q.tail {
						q.unlink(w)
						q.link(w)
					}
					s.mu.Unlock()
					continue
				}
				q.unlink(w)
				w.reservation = reservation
				if w.ready != nil {
					q.free(w.n)
					close(w.ready)
					s.mu.Unlock()
					continue
				}
				if w.stop != nil {
					w.stop()
				}
				if w.flow != nil {
					w.flow.running = true
				}
				s.mu.Unlock()
				go func() {
					defer s.finishAsync(dir, w, true)
					_, _ = s.write(w.ctx, dir, cost, w.reservation, w.send)
				}()
				continue
			}
		}
		s.mu.Unlock()
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
		case <-tick:
		case <-q.wake:
			if tick != nil {
				timer.Stop()
			}
		}
	}
}

type bandwidthWork struct {
	prev, next  *bandwidthWork
	queued      bool
	n           int // retained queue bytes
	wireBytes   int // charge in the absence of previously paid quanta
	remaining   int
	reservation bandwidthReservation

	ready chan struct{} // synchronous waiter, nil for asynchronous handoffs
	err   error

	ctx     context.Context
	flow    *BandwidthFlow
	send    func() (int, error)
	release func()
	holds   []*BandwidthIdleHold
	stop    func() bool
}

type bandwidthReservation struct {
	epoch       uint64
	refundUntil uint64
}

// All queue mutations and token arithmetic run under the shaper mutex.
type bandwidthQueue struct {
	rate, credit, epoch uint64
	addedCredit         uint64
	last                time.Time

	head, tail *bandwidthWork
	items      int
	bytes      int
	space      chan struct{}
	wake       chan struct{}
	stopped    chan struct{}
}

func (q *bandwidthQueue) fits(n int) bool {
	return q.items < bandwidthQueueItems && n <= bandwidthQueueBytes-q.bytes
}

func (q *bandwidthQueue) firstReady() *bandwidthWork {
	for w := q.head; w != nil; w = w.next {
		if w.flow == nil || !w.flow.running {
			return w
		}
	}
	return nil
}

func (q *bandwidthQueue) append(w *bandwidthWork) {
	q.link(w)
	q.items++
	q.bytes += w.n
}

func (q *bandwidthQueue) link(w *bandwidthWork) {
	w.prev, w.queued = q.tail, true
	if q.tail == nil {
		q.head = w
	} else {
		q.tail.next = w
	}
	q.tail = w
}

func (q *bandwidthQueue) unlink(w *bandwidthWork) {
	if w.prev == nil {
		q.head = w.next
	} else {
		w.prev.next = w.next
	}
	if w.next == nil {
		q.tail = w.prev
	} else {
		w.next.prev = w.prev
	}
	w.prev, w.next, w.queued = nil, nil, false
}

func (q *bandwidthQueue) free(n int) {
	q.items--
	q.bytes -= n
	q.signalSpace()
}

func (q *bandwidthQueue) signalSpace() {
	if q.space != nil {
		close(q.space)
		q.space = nil
	}
}

func (q *bandwidthQueue) signalWorker() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *bandwidthQueue) setRate(rate uint64, now time.Time) {
	if rate == q.rate {
		return
	}
	if q.rate == 0 {
		q.epoch++ // Outstanding writes from a prior limited interval cannot refund into this one.
		q.addedCredit = 0
	} else {
		q.refill(now)
	}
	if rate == 0 {
		q.credit = 0
		// A later re-enable starts empty, including payments on queued packets.
		for w := q.head; w != nil; w = w.next {
			if w.remaining != w.wireBytes {
				w.remaining = w.wireBytes
			}
		}
		q.signalSpace()
	}
	q.rate, q.last = rate, now
	q.signalWorker()
}

func (q *bandwidthQueue) take(n int) (bandwidthReservation, time.Duration) {
	if q.rate == 0 || n == 0 {
		return bandwidthReservation{}, 0
	}
	q.refill(time.Now())
	cost := bandwidthCost(n)
	if cost > q.credit {
		return bandwidthReservation{}, bandwidthWait(cost-q.credit, q.rate)
	}
	q.credit -= cost
	headroom := bandwidthBurstCredit - q.credit
	refundUntil := q.addedCredit + min(headroom, ^uint64(0)-q.addedCredit)
	return bandwidthReservation{epoch: q.epoch, refundUntil: refundUntil}, 0
}

func (q *bandwidthQueue) refund(reservation bandwidthReservation, credit uint64) {
	if q.rate == 0 || reservation.epoch != q.epoch {
		return
	}
	q.refill(time.Now())
	// Credit added since the reservation may already have been spent. Only
	// refund what could still fit if there had been no intervening spending.
	// Otherwise a late refund could add to a burst already spent by another flow.
	if reservation.epoch == q.epoch && reservation.refundUntil > q.addedCredit {
		q.addCredit(min(credit, reservation.refundUntil-q.addedCredit))
		q.signalWorker()
	}
}

func (q *bandwidthQueue) addCredit(credit uint64) {
	q.credit += credit
	q.addedCredit += credit
	if q.addedCredit < credit {
		q.epoch++ // Expire outstanding refunds when the watermark wraps.
	}
}

func (q *bandwidthQueue) refill(now time.Time) {
	elapsed := now.Sub(q.last)
	if elapsed <= 0 {
		return
	}
	q.last = now
	remaining := bandwidthBurstCredit - q.credit
	// Compare before multiplying to avoid overflow after long idle intervals.
	if remaining == 0 || elapsed >= bandwidthWait(remaining, q.rate) {
		q.addCredit(remaining)
		return
	}
	q.addCredit(uint64(elapsed) * q.rate)
}

func bandwidthCost(n int) uint64 { return uint64(n) * bandwidthCreditPerByte }

func bandwidthWait(credit, rate uint64) time.Duration {
	return time.Duration(1 + (credit-1)/rate) // ceil for positive credit
}
