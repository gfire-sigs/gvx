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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestBandwidthIndependentSandboxesAndDirections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := NewBandwidthShaper(BandwidthRates{TXBPS: 8, RXBPS: 32})
		defer a.Close()
		b := NewBandwidthShaper(BandwidthRates{TXBPS: 16})
		defer b.Close()
		start := time.Now()
		type handoff struct {
			name string
			when time.Duration
		}
		sent := make(chan handoff, 4)
		enqueue := func(s *BandwidthShaper, dir BandwidthDirection, n int, name string) {
			t.Helper()
			if !s.Enqueue(t.Context(), dir, n, func() (int, error) {
				sent <- handoff{name, time.Since(start)}
				return n, nil
			}, nil) {
				t.Fatalf("enqueue %s was rejected", name)
			}
		}
		enqueue(a, BandwidthTX, 2, "first sandbox TX")
		enqueue(a, BandwidthTX, 1, "first sandbox next TX")
		enqueue(a, BandwidthRX, 2, "first sandbox RX")
		enqueue(b, BandwidthTX, 2, "second sandbox TX")
		for _, want := range []handoff{
			{"first sandbox RX", 500 * time.Millisecond},
			{"second sandbox TX", time.Second},
			{"first sandbox TX", 2 * time.Second},
			{"first sandbox next TX", 3 * time.Second},
		} {
			if got := <-sent; got != want {
				t.Fatalf("handoff = %+v, want %+v", got, want)
			}
		}
	})
}

func TestBandwidthDatagramWaitsWholeAndHoldsIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 32})
		defer s.Close()
		var hold BandwidthIdleHold
		start := time.Now()
		sent := make(chan time.Duration, 1)
		shapeDone := make(chan error, 1)
		go func() {
			_, err := s.ShapeDatagram(t.Context(), BandwidthTX, 13, func() (int, error) {
				sent <- time.Since(start)
				return 13, nil
			}, &hold)
			shapeDone <- err
		}()
		synctest.Wait()
		if !hold.Pending() {
			t.Fatal("paced datagram did not hold the UDP session open")
		}
		if err := hold.Wait(t.Context()); err != nil {
			t.Fatalf("wait for UDP idle hold: %v", err)
		}
		if got := <-sent; got != 3250*time.Millisecond {
			t.Fatalf("13-byte datagram handoff at %v, want 3.25s", got)
		}
		if err := <-shapeDone; err != nil {
			t.Fatalf("shape whole datagram: %v", err)
		}
		if hold.Pending() {
			t.Fatal("completed datagram still holds the UDP session open")
		}
	})
}

func TestBandwidthQueueCancellationReleasesNonHeadDatagram(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 8})
		defer s.Close()
		parent := t.Context()
		start := time.Now()
		if !s.Enqueue(parent, BandwidthTX, 64, func() (int, error) { return 64, nil }, nil) {
			t.Fatal("enqueue head datagram was rejected")
		}
		ctx, cancel := context.WithCancel(parent)
		defer cancel()
		var hold BandwidthIdleHold
		var writes, releases int
		if !s.Enqueue(ctx, BandwidthTX, 8, func() (int, error) {
			writes++
			return 8, nil
		}, func() {
			if !hold.Pending() {
				t.Error("UDP idle hold ended before buffer release")
			}
			releases++
		}, &hold) {
			t.Fatal("enqueue cancelable datagram was rejected")
		}
		cancel()
		synctest.Wait()
		if writes != 0 || releases != 1 || hold.Pending() {
			t.Fatalf("canceled datagram: writes=%d, releases=%d, held=%t; want 0, 1, false", writes, releases, hold.Pending())
		}
		if got := time.Since(start); got != 0 {
			t.Fatalf("canceled datagram released at %v, want immediate release rather than waiting for the head", got)
		}
	})
}

func TestBandwidthCanceledShapeNeverWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 8})
		defer s.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		returned := make(chan error, 1)
		go func() {
			_, err := s.Shape(ctx, BandwidthTX, 8, func() (int, error) {
				t.Error("canceled shape invoked its writer")
				return 8, nil
			})
			returned <- err
		}()
		synctest.Wait()
		cancel()
		if got := <-returned; !errors.Is(got, context.Canceled) {
			t.Fatalf("canceled shape error = %v, want context.Canceled", got)
		}
	})
}

func TestBandwidthQueueLimitsWholeUnits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		queued int
	}{
		{"bytes", bandwidthMaxUnit, bandwidthQueueBytes / bandwidthMaxUnit},
		{"items including empty datagrams", 0, bandwidthQueueItems - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := NewBandwidthShaper(BandwidthRates{TXBPS: 1})
				defer s.Close()
				ctx := t.Context()
				writes, releases := 0, 0
				send := func() (int, error) { writes++; return tc.size, nil }
				release := func() { releases++ }
				if tc.size == 0 && !s.Enqueue(ctx, BandwidthTX, 1, send, release) {
					t.Fatal("enqueue head datagram was rejected")
				}
				for i := range tc.queued {
					if !s.Enqueue(ctx, BandwidthTX, tc.size, send, release) {
						t.Fatalf("queued unit %d was rejected before reaching capacity", i)
					}
				}
				if s.Enqueue(ctx, BandwidthTX, tc.size, send, release) {
					t.Fatal("over-capacity unit was accepted")
				}
				if releases != 1 {
					t.Fatalf("rejected unit releases = %d, want 1", releases)
				}
				datagramCtx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				n, err := s.ShapeDatagram(datagramCtx, BandwidthTX, tc.size, send)
				if n != 0 || !errors.Is(err, errBandwidthQueueFull) {
					t.Fatalf("over-capacity synchronous datagram = (%d, %v), want (0, queue full)", n, err)
				}
				s.Close()
				wantReleased := tc.queued + 1
				if tc.size == 0 {
					wantReleased++
				}
				if writes != 0 || releases != wantReleased {
					t.Fatalf("after close: writes=%d, releases=%d; want 0, %d", writes, releases, wantReleased)
				}
			})
		})
	}
}

func TestBandwidthPairUpdateRepricesQueuedHandoffs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 8, RXBPS: 16})
		defer s.Close()
		start := time.Now()
		atTX, atRX := make(chan time.Duration, 1), make(chan time.Duration, 1)
		enqueue := func(dir BandwidthDirection, n int, at chan<- time.Duration) {
			t.Helper()
			if !s.Enqueue(t.Context(), dir, n, func() (int, error) {
				at <- time.Since(start)
				return n, nil
			}, nil) {
				t.Fatalf("enqueue %d-byte datagram in direction %v was rejected", n, dir)
			}
		}
		enqueue(BandwidthTX, 1, atTX)
		enqueue(BandwidthRX, 8, atRX)
		time.Sleep(250 * time.Millisecond)
		wantRates := BandwidthRates{TXBPS: 24}
		s.SetRates(wantRates)
		if got := s.Rates(); got != wantRates {
			t.Fatalf("installed rates = %+v, want %+v", got, wantRates)
		}
		if got := <-atRX; got != 250*time.Millisecond {
			t.Fatalf("cleared RX released at %v, want 250ms", got)
		}
		if got := <-atTX; got != 500*time.Millisecond {
			t.Fatalf("increased TX released at %v, want 500ms with credit earned before update", got)
		}
	})
}

func TestBandwidthNewLimitCannotSpendOldRefund(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rates := BandwidthRates{TXBPS: 8}
		s := NewBandwidthShaper(rates)
		defer s.Close()
		started := make(chan struct{})
		unblock := make(chan struct{})
		finished := make(chan struct{})
		go func() {
			_, _ = s.Shape(t.Context(), BandwidthTX, 2, func() (int, error) {
				close(started)
				<-unblock
				return 0, io.ErrClosedPipe
			})
			close(finished)
		}()
		<-started
		s.SetRates(BandwidthRates{})
		time.Sleep(time.Hour)
		s.SetRates(rates)
		start := time.Now()
		close(unblock)
		<-finished
		if _, err := s.Shape(t.Context(), BandwidthTX, 1, func() (int, error) { return 1, nil }); err != nil {
			t.Fatalf("shape after re-enable: %v", err)
		}
		if got := time.Since(start); got != time.Second {
			t.Fatalf("newly limited handoff waited %v, want 1s without idle or old refund credit", got)
		}
	})
}

func TestBandwidthLateRefundDoesNotAddToSpentBurst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const blockedBytes = 16 << 10
		s := NewBandwidthShaper(BandwidthRates{TXBPS: bandwidthMaxUnit * 8})
		defer s.Close()
		ctx := t.Context()
		time.Sleep(time.Second) // Refill the initial burst before reserving.
		started, unblock, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			_, _ = s.Shape(ctx, BandwidthTX, blockedBytes, func() (int, error) {
				close(started)
				<-unblock
				return 0, io.ErrClosedPipe
			})
			close(finished)
		}()
		<-started
		time.Sleep(time.Second)
		start := time.Now()
		_, err := s.Shape(ctx, BandwidthTX, bandwidthMaxUnit, func() (int, error) {
			return bandwidthMaxUnit, nil
		})
		close(unblock)
		<-finished
		if err != nil || time.Since(start) != 0 {
			t.Fatalf("other flow full burst: waited %v, error %v; want immediate write", time.Since(start), err)
		}
		if _, err := s.Shape(ctx, BandwidthTX, blockedBytes, func() (int, error) { return blockedBytes, nil }); err != nil {
			t.Fatalf("next write after late refund: %v", err)
		}
		if got := time.Since(start); got != time.Second/16 {
			t.Fatalf("next write waited %v, want %v after another flow already spent the full burst", got, time.Second/16)
		}
	})
}

func TestBandwidthCopySettlesOnlyUnsentBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 8})
		defer s.Close()
		start := time.Now()
		n, err := s.Copy(t.Context(), BandwidthTX, bandwidthShortWriter{}, bytes.NewReader([]byte("abcd")))
		if n != 2 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("copy through short writer = (%d, %v), want (2, io.ErrShortWrite)", n, err)
		}
		if got := time.Since(start); got != 4*time.Second {
			t.Fatalf("initial write waited %v, want 4s for reserved bytes", got)
		}
		if _, err := s.Shape(t.Context(), BandwidthTX, 3, func() (int, error) { return 3, nil }); err != nil {
			t.Fatalf("shape after short write: %v", err)
		}
		if got := time.Since(start); got != 5*time.Second {
			t.Fatalf("next handoff at %v, want 5s using only the 2 unsent bytes of refunded credit", got)
		}
	})
}

type bandwidthShortWriter struct{}

func (bandwidthShortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestBandwidthBlockedWriteDoesNotBlockSameDirection(t *testing.T) {
	for _, async := range []bool{false, true} {
		name := "synchronous write"
		if async {
			name = "enqueued write"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := NewBandwidthShaper(BandwidthRates{TXBPS: 8})
				defer s.Close()
				ctx := t.Context()
				start := time.Now()
				started, unblock, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
				defer func() {
					close(unblock)
					<-finished
				}()
				blocked := func() (int, error) {
					_ = s.Rates() // A callback must be able to acquire the shaper lock.
					close(started)
					<-unblock
					return 1, nil
				}
				if async {
					if !s.Enqueue(ctx, BandwidthTX, 1, blocked, func() { close(finished) }) {
						t.Fatal("enqueue first write was rejected")
					}
				} else {
					go func() {
						defer close(finished)
						_, _ = s.Shape(ctx, BandwidthTX, 1, blocked)
					}()
				}
				<-started
				deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				sent := make(chan time.Duration, 1)
				if !s.Enqueue(deadline, BandwidthTX, 1, func() (int, error) {
					sent <- time.Since(start)
					return 1, nil
				}, nil) {
					t.Fatal("enqueue unrelated write was rejected")
				}
				select {
				case got := <-sent:
					if got != 2*time.Second {
						t.Fatalf("unrelated write at %v, want 2s while first write remains blocked", got)
					}
				case <-deadline.Done():
					t.Fatal("unrelated write did not run while the first write was blocked")
				}
			})
		})
	}
}

func TestBandwidthCloseCancelsQueuedShape(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 8})
		defer s.Close()
		returned := make(chan error, 1)
		go func() {
			_, err := s.Shape(t.Context(), BandwidthTX, 8, func() (int, error) {
				t.Error("closed shaper invoked its queued writer")
				return 8, nil
			})
			returned <- err
		}()
		synctest.Wait()
		s.Close()
		if got := <-returned; !errors.Is(got, net.ErrClosed) {
			t.Fatalf("closed shape error = %v, want net.ErrClosed", got)
		}
	})
}

func TestBandwidthRefillAfterLongIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: MaxBandwidthBPS})
		defer s.Close()
		time.Sleep(24 * time.Hour)
		start := time.Now()
		if _, err := s.Shape(t.Context(), BandwidthTX, bandwidthMaxUnit, func() (int, error) {
			return bandwidthMaxUnit, nil
		}); err != nil {
			t.Fatalf("shape maximum unit after idle: %v", err)
		}
		if got := time.Since(start); got != 0 {
			t.Fatalf("maximum unit after idle waited %v, want immediate handoff from full burst", got)
		}
	})
}

func TestBandwidthOrderedFlowSurvivesRateClear(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: 8})
		defer s.Close()
		ctx := t.Context()
		var same, other BandwidthFlow
		started, unblock := make(chan struct{}), make(chan struct{})
		defer func() {
			select {
			case <-unblock:
			default:
				close(unblock)
			}
		}()
		if !s.EnqueueOrdered(ctx, BandwidthTX, &same, 1, func() (int, error) {
			close(started)
			<-unblock
			return 1, nil
		}, nil) {
			t.Fatal("enqueue first write was rejected")
		}
		<-started
		sent := make(chan int, 3)
		enqueue := func(flow *BandwidthFlow, n int) {
			t.Helper()
			if !s.EnqueueOrdered(ctx, BandwidthTX, flow, 1, func() (int, error) {
				sent <- n
				return 1, nil
			}, nil) {
				t.Fatalf("enqueue write %d was rejected", n)
			}
		}
		enqueue(&same, 2)
		s.SetRates(BandwidthRates{})
		if s.Enabled(BandwidthTX) || !same.Pending() {
			t.Fatal("rate clear should disable shaping but not clear the pending flow")
		}
		enqueue(&same, 3)
		enqueue(&other, 4)
		if got := <-sent; got != 4 {
			t.Fatalf("while first send is blocked, write %d ran; only unrelated write 4 may run", got)
		}
		synctest.Wait()
		select {
		case got := <-sent:
			t.Fatalf("write %d overtook the blocked same-flow write", got)
		default:
		}
		close(unblock)
		for _, want := range []int{2, 3} {
			if got := <-sent; got != want {
				t.Fatalf("ordered flow write = %d, want %d", got, want)
			}
		}
		synctest.Wait()
		if same.Pending() || other.Pending() {
			t.Fatal("completed sends still own their flows")
		}
	})
}

func TestBandwidthPacketPacesItsWireCostAndSendsOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: bandwidthMaxUnit * 8})
		defer s.Close()
		ctx := t.Context()
		writes := make(chan time.Duration, 2)
		released := 0
		if s.EnqueuePacket(ctx, BandwidthTX, bandwidthQueueBytes+1, 1, func() (int, error) {
			t.Error("packet bigger than retained-byte capacity was written")
			return 1, nil
		}, func() { released++ }) {
			t.Fatal("packet bigger than retained-byte capacity was accepted")
		}
		const retainedBytes = 1024
		const wireBytes = bandwidthQueueBytes + bandwidthMaxUnit/2
		start := time.Now()
		if !s.EnqueuePacket(ctx, BandwidthTX, retainedBytes, wireBytes, func() (int, error) {
			writes <- time.Since(start)
			return wireBytes, nil
		}, func() { released++ }) {
			t.Fatal("packet was rejected despite fitting the retained-byte capacity")
		}
		want := time.Duration(wireBytes) * time.Second / bandwidthMaxUnit
		if got := <-writes; got != want {
			t.Fatalf("packet handoff at %v, want %v for %d wire bytes", got, want, wireBytes)
		}
		synctest.Wait()
		if len(writes) != 0 || released != 2 {
			t.Fatalf("extra sends=%d, releases=%d; want 0 extra sends and one release per packet", len(writes), released)
		}
	})
}

func TestBandwidthCanceledPacketCannotRefundPriorQuanta(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewBandwidthShaper(BandwidthRates{TXBPS: bandwidthMaxUnit * 8})
		defer s.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		released := make(chan struct{})
		if !s.EnqueuePacket(ctx, BandwidthTX, 1024, 2*bandwidthMaxUnit, func() (int, error) {
			t.Error("canceled multi-quantum packet was written")
			return 2 * bandwidthMaxUnit, nil
		}, func() { close(released) }) {
			t.Fatal("enqueue multi-quantum packet was rejected")
		}
		time.Sleep(1250 * time.Millisecond) // The first quantum has been consumed.
		cancel()
		<-released
		start := time.Now()
		_, err := s.Shape(t.Context(), BandwidthTX, bandwidthMaxUnit, func() (int, error) {
			return bandwidthMaxUnit, nil
		})
		if err != nil || time.Since(start) != 750*time.Millisecond {
			t.Fatalf("next full burst waited %v with error %v, want 750ms without refund of the prior quantum", time.Since(start), err)
		}
	})
}
