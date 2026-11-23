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
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

var (
	schedulerIPv4 = PolicyTuple{Source: netip.MustParseAddr("192.0.2.2"), Destination: netip.MustParseAddr("198.51.100.2")}
	schedulerIPv6 = PolicyTuple{IPv6: true, Source: netip.MustParseAddr("2001:db8::2"), Destination: netip.MustParseAddr("2001:db8::3")}
)

func schedulerLimit(rate uint64) PolicyLimit {
	return PolicyLimit{RateBPS: rate, BurstBytes: 128 << 10, QueueBytes: 128 << 10}
}

func schedulerPolicy(t *testing.T, tx, rx PolicyLimit) *NATPolicy {
	t.Helper()
	p := NewNATPolicy(schedulerCompile(t, schedulerAcceptRules, schedulerAcceptRules, tx, rx), netip.AddrPort{})
	t.Cleanup(p.Close)
	return p
}

func schedulerNoEvent[T any](t *testing.T, ch <-chan T, operation string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s completed early", operation)
	default:
	}
}

func schedulerEvent[T any](t *testing.T, ch <-chan T, operation string) T {
	t.Helper()
	select {
	case got := <-ch:
		return got
	default:
		t.Fatalf("%s did not complete", operation)
		var zero T
		return zero
	}
}

func awaitSchedulerEvent[T any](t *testing.T, ctx context.Context, ch <-chan T, operation string) T {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-ctx.Done():
		t.Fatalf("%s did not complete: %v", operation, ctx.Err())
		var zero T
		return zero
	}
}

// pinPolicyCommit keeps a canceled dial in flight until the test lets it settle.
func pinPolicyCommit(t *testing.T, ctx context.Context, p *NATPolicy, candidate *CompiledPolicy, lateConn net.Conn) func() {
	t.Helper()
	started, canceled, settle := make(chan struct{}), make(chan struct{}), make(chan struct{})
	dialed, committed := make(chan error, 1), make(chan error, 1)
	release := sync.OnceFunc(func() { close(settle) })
	t.Cleanup(release)
	go func() {
		_, err := p.Dial(t.Context(), PolicyInput, func(ctx context.Context) (net.Conn, error) {
			close(started)
			select {
			case <-ctx.Done():
				close(canceled)
			case <-settle:
				return nil, ctx.Err()
			}
			<-settle
			if lateConn != nil {
				return lateConn, nil
			}
			return nil, ctx.Err()
		}, schedulerIPv4)
		dialed <- err
	}()
	awaitSchedulerEvent(t, ctx, started, "start old dial")
	go func() { committed <- p.Commit(candidate) }()
	awaitSchedulerEvent(t, ctx, canceled, "cancel old dial at cutover")
	schedulerNoEvent(t, committed, "replacement while the old dial is pinned")
	return func() {
		t.Helper()
		release()
		if err := awaitSchedulerEvent(t, ctx, dialed, "settle old dial"); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("old Dial = %v, want %v", err, ErrPolicyDenied)
		}
		if err := awaitSchedulerEvent(t, ctx, committed, "publish replacement"); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
}

func TestNATPolicyAggregatesTXAcrossFamiliesAndProducers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, schedulerLimit(12), schedulerLimit(80))
		txPacket, txRelay, rx := make(chan struct{}, 1), make(chan error, 1), make(chan struct{}, 1)
		if !p.Enqueue(PolicyInput, 1, func() { txPacket <- struct{}{} }, nil, schedulerIPv4) {
			t.Fatal("enqueue first TX packet")
		}
		go func() {
			txRelay <- p.Send(t.Context(), PolicyInput, 1, func() error { return nil }, schedulerIPv6)
		}()
		if !p.Enqueue(PolicyOutput, 1, func() { rx <- struct{}{} }, nil, schedulerIPv4) {
			t.Fatal("enqueue RX packet")
		}
		synctest.Wait()
		schedulerNoEvent(t, txPacket, "packet without initial credit")
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		schedulerEvent(t, rx, "independent RX budget")
		schedulerNoEvent(t, txPacket, "first TX packet")
		time.Sleep(566666666 * time.Nanosecond)
		synctest.Wait()
		schedulerNoEvent(t, txPacket, "first TX packet before one full byte")
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		schedulerEvent(t, txPacket, "first TX packet at its fractional byte boundary")
		schedulerNoEvent(t, txRelay, "relay sharing packet credit")
		time.Sleep(666666667 * time.Nanosecond)
		synctest.Wait()
		if err := schedulerEvent(t, txRelay, "second TX handoff"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNATPolicyInstanceReplacementDoesNotChangeAnotherBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := schedulerPolicy(t, schedulerLimit(8), PolicyLimit{})
		b := schedulerPolicy(t, schedulerLimit(8), PolicyLimit{})
		oldSent, oldDisposed, otherSent := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
		if !a.Enqueue(PolicyInput, 2, func() { oldSent <- struct{}{} }, func() { oldDisposed <- struct{}{} }, schedulerIPv4) ||
			!b.Enqueue(PolicyInput, 2, func() { otherSent <- struct{}{} }, nil, schedulerIPv4) {
			t.Fatal("enqueue for both policy instances")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		candidate := schedulerCompile(t, schedulerDropRules, schedulerAcceptRules, schedulerLimit(32), schedulerLimit(8))
		if err := a.Commit(candidate); err != nil {
			t.Fatal(err)
		}
		schedulerEvent(t, oldDisposed, "disposal of queued work denied by replacement")
		if a.Allow(PolicyInput, schedulerIPv4) || !a.Allow(PolicyInput, schedulerIPv6) || !b.Allow(PolicyInput, schedulerIPv4) {
			t.Fatal("replacement did not preserve family or instance isolation")
		}
		nextTX, nextRX := make(chan struct{}, 1), make(chan struct{}, 1)
		if !a.Enqueue(PolicyInput, 2, func() { nextTX <- struct{}{} }, nil, schedulerIPv6) ||
			!a.Enqueue(PolicyOutput, 1, func() { nextRX <- struct{}{} }, nil, schedulerIPv6) {
			t.Fatal("enqueue under replacement policy")
		}
		time.Sleep(250 * time.Millisecond)
		synctest.Wait()
		schedulerEvent(t, nextTX, "TX after one preserved byte and one byte at the new rate")
		schedulerNoEvent(t, nextRX, "newly limited RX direction without initial credit")
		schedulerNoEvent(t, otherSent, "second instance at its original rate")
		time.Sleep(750 * time.Millisecond)
		synctest.Wait()
		schedulerEvent(t, nextRX, "newly limited RX direction after earning one byte")
		schedulerEvent(t, otherSent, "independent budget in second instance")
		schedulerNoEvent(t, oldSent, "old IPv4 work denied at cutover")
	})
}

func TestNATPolicyCommitDoesNotRefillWhileBlocked(t *testing.T) {
	ctx := testContext(t)
	p := schedulerPolicy(t, PolicyLimit{}, schedulerLimit(8))
	sent := make(chan struct{}, 1)
	if !p.Enqueue(PolicyOutput, 1, func() { sent <- struct{}{} }, nil, schedulerIPv4) {
		t.Fatal("enqueue under original policy")
	}
	candidate := schedulerCompile(t, schedulerAcceptRules, schedulerAcceptRules, PolicyLimit{}, schedulerLimit(1))
	finish := pinPolicyCommit(t, ctx, p, candidate, nil)
	if p.Allow(PolicyOutput, schedulerIPv4) {
		t.Error("packet hook admitted traffic while cutover was blocked")
	}
	// One second behind the gate would earn a byte at the old rate.
	// synctest cannot advance time while Commit waits on the pinned RWMutex.
	select {
	case <-sent:
		t.Fatal("handoff during blocked cutover")
	case <-time.After(time.Second):
	case <-ctx.Done():
		t.Fatal("timed out holding the handoff")
	}
	finish()
	probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := p.Send(probeCtx, PolicyOutput, 0, func() error { return nil }, schedulerIPv4); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("zero-byte probe behind paced work = %v, want context.DeadlineExceeded", err)
	}
	schedulerNoEvent(t, sent, "handoff using credit from the blocked interval")
}

type schedulerWaitingContext struct {
	context.Context
	waiting chan<- struct{}
}

func (c schedulerWaitingContext) Done() <-chan struct{} {
	select {
	case c.waiting <- struct{}{}:
	default:
	}
	return c.Context.Done()
}

func TestNATPolicyStreamWaitingAtCutoverCanCancel(t *testing.T) {
	ctx := testContext(t)
	p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
	candidate := schedulerCompile(t, schedulerAcceptRules, schedulerAcceptRules, PolicyLimit{}, PolicyLimit{})
	finish := pinPolicyCommit(t, ctx, p, candidate, nil)
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()
	waiting, done := make(chan struct{}, 1), make(chan error, 1)
	go func() {
		done <- p.CopyStream(schedulerWaitingContext{streamCtx, waiting}, PolicyInput, dst, src, schedulerIPv4)
	}()
	awaitSchedulerEvent(t, ctx, waiting, "stream waiting on cutover")
	schedulerNoEvent(t, done, "stream before cancellation")
	cancel()
	if err := awaitSchedulerEvent(t, ctx, done, "canceled stream during cutover"); !errors.Is(err, context.Canceled) {
		t.Errorf("CopyStream = %v, want context.Canceled", err)
	}
	finish()
}

func TestNATPolicyCloseStopsAdmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, schedulerLimit(8), PolicyLimit{})
		sent, disposed := make(chan struct{}, 1), make(chan struct{}, 1)
		if !p.Enqueue(PolicyInput, 10, func() { sent <- struct{}{} }, func() { disposed <- struct{}{} }, schedulerIPv4) {
			t.Fatal("enqueue before close")
		}
		p.Close()
		schedulerEvent(t, disposed, "queued disposal after close")
		schedulerNoEvent(t, sent, "queued handoff after close")
		candidate := schedulerCompile(t, schedulerAcceptRules, schedulerAcceptRules, PolicyLimit{}, PolicyLimit{})
		if err := p.Commit(candidate); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("Commit after close = %v, want %v", err, ErrPolicyDenied)
		}
		if release, ok := p.Begin(PolicyOutput, schedulerIPv6); ok {
			release()
			t.Error("Begin admitted traffic after close")
		}
		if err := p.Send(t.Context(), PolicyInput, 0, func() error {
			t.Error("Send admitted traffic after close")
			return nil
		}, schedulerIPv4); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("Send after close = %v, want %v", err, ErrPolicyDenied)
		}
	})
}

func TestNATPolicyQueueBoundsWholeUnitsAndCancelsQueuedWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := schedulerLimit(8)
		p := schedulerPolicy(t, limit, limit)
		sent := make(chan struct{}, 1)
		txDisposed, rxDisposed := make(chan struct{}, 2), make(chan struct{}, policyMaxItems+1)
		if !p.Enqueue(PolicyInput, limit.QueueBytes, func() { sent <- struct{}{} }, func() { txDisposed <- struct{}{} }, schedulerIPv4) {
			t.Fatal("enqueue one full TX bucket")
		}
		if p.Enqueue(PolicyInput, 1, func() { sent <- struct{}{} }, func() { txDisposed <- struct{}{} }, schedulerIPv4) {
			t.Fatal("accepted a TX datagram beyond the byte bound")
		}
		schedulerEvent(t, txDisposed, "byte overflow disposal")
		// Put a paced packet first so the worker cannot drain the zero-byte units.
		if !p.Enqueue(PolicyOutput, 1, func() { sent <- struct{}{} }, func() { rxDisposed <- struct{}{} }, schedulerIPv4) {
			t.Fatal("enqueue RX packet independently of full TX")
		}
		for i := 1; i < policyMaxItems; i++ {
			if !p.Enqueue(PolicyOutput, 0, func() { sent <- struct{}{} }, func() { rxDisposed <- struct{}{} }, schedulerIPv4) {
				t.Fatalf("rejected RX item %d below item bound", i)
			}
		}
		if p.Enqueue(PolicyOutput, 0, func() { sent <- struct{}{} }, func() { rxDisposed <- struct{}{} }, schedulerIPv4) {
			t.Fatal("accepted an empty RX datagram beyond the item bound")
		}
		schedulerEvent(t, rxDisposed, "item overflow disposal")
		p.Close()
		if len(txDisposed) != 1 || len(rxDisposed) != policyMaxItems {
			t.Errorf("Close disposed TX=%d and RX=%d pending units, want 1 and %d", len(txDisposed), len(rxDisposed), policyMaxItems)
		}
		schedulerNoEvent(t, sent, "canceled datagram")
	})
}

func TestNATPolicyCommitDropsWholeDatagramWhenQueueShrinks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, PolicyLimit{RateBPS: 8, BurstBytes: 65537, QueueBytes: 131074}, PolicyLimit{})
		firstSent, secondSent, secondDisposed := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
		if !p.Enqueue(PolicyInput, 65537, func() { firstSent <- struct{}{} }, nil, schedulerIPv4) ||
			!p.Enqueue(PolicyInput, 65537, func() { secondSent <- struct{}{} }, func() { secondDisposed <- struct{}{} }, schedulerIPv4) {
			t.Fatal("enqueue two whole datagrams at the original byte limit")
		}
		limit := PolicyLimit{RateBPS: 8 * 65537, BurstBytes: 65537, QueueBytes: 65537}
		candidate := schedulerCompile(t, schedulerAcceptRules, schedulerAcceptRules, limit, PolicyLimit{})
		if err := p.Commit(candidate); err != nil {
			t.Fatal(err)
		}
		schedulerEvent(t, secondDisposed, "disposal of datagram beyond new capacity")
		time.Sleep(time.Second)
		synctest.Wait()
		schedulerEvent(t, firstSent, "first queued datagram")
		schedulerNoEvent(t, secondSent, "datagram discarded at cutover")
	})
}

func TestNATPolicySendCancellationReleasesQueuedCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := schedulerLimit(8)
		p := schedulerPolicy(t, limit, PolicyLimit{})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		sent, done := make(chan struct{}, 1), make(chan error, 1)
		go func() {
			done <- p.Send(ctx, PolicyInput, limit.QueueBytes, func() error {
				sent <- struct{}{}
				return nil
			}, schedulerIPv4)
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := schedulerEvent(t, done, "canceled Send"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Send = %v, want context.Canceled", err)
		}
		if !p.Enqueue(PolicyInput, limit.QueueBytes, func() {}, nil, schedulerIPv4) {
			t.Error("canceled Send kept its space in the queue")
		}
		schedulerNoEvent(t, sent, "canceled queued callback")
	})
}

func TestPolicyDatagramRejectionDoesNotRefreshIdle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 100 * time.Millisecond
		limit := schedulerLimit(8)
		p := NewNATPolicy(schedulerCompile(t, schedulerDropRules, schedulerAcceptRules, limit, PolicyLimit{}), netip.AddrPort{})
		defer p.Close()
		if !p.Enqueue(PolicyInput, limit.QueueBytes, func() {}, nil, schedulerIPv6) {
			t.Fatal("fill TX queue")
		}
		clock := newActivityClock()
		expired := make(chan struct{})
		clock.startIdleTimer(idle, func() { close(expired) }, nil)
		defer clock.stop()
		time.Sleep(idle / 2)
		send := func() (int, error) {
			t.Error("a rejected datagram reached the writer")
			return 1, nil
		}
		if err := p.sendDatagram(t.Context(), PolicyInput, 1, clock, send, schedulerIPv4); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("denied datagram = %v, want %v", err, ErrPolicyDenied)
		}
		if err := p.sendDatagram(t.Context(), PolicyInput, 1, clock, send, schedulerIPv6); !errors.Is(err, ErrPolicyQueueFull) {
			t.Errorf("datagram beyond capacity = %v, want %v", err, ErrPolicyQueueFull)
		}
		time.Sleep(idle / 2)
		synctest.Wait()
		schedulerEvent(t, expired, "session expiry despite rejected datagrams")
	})
}

func TestPolicyDatagramHoldSurvivesCancellationDuringWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 100 * time.Millisecond
		p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
		clock := newActivityClock()
		expired := make(chan struct{})
		clock.startIdleTimer(idle, func() { close(expired) }, nil)
		defer clock.stop()
		started, unblock := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(unblock) })
		defer release()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- p.sendDatagram(ctx, PolicyOutput, 1, clock, func() (int, error) {
				close(started)
				<-unblock
				return 0, net.ErrClosed
			}, schedulerIPv4)
		}()
		<-started
		cancel()
		time.Sleep(idle * 2)
		synctest.Wait()
		schedulerNoEvent(t, done, "canceled work with a write still in flight")
		schedulerNoEvent(t, expired, "expiry with a write still in flight")
		release()
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if err := schedulerEvent(t, done, "write completion"); !errors.Is(err, net.ErrClosed) {
			t.Errorf("write result = %v, want %v", err, net.ErrClosed)
		}
		schedulerEvent(t, expired, "expiry after unsuccessful write completion")
	})
}

func TestPolicyDatagramQueueDropsReleaseIdleHold(t *testing.T) {
	for _, action := range []string{"rule replacement", "policy close"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const idle = 100 * time.Millisecond
				limit := schedulerLimit(8)
				p := schedulerPolicy(t, limit, PolicyLimit{})
				clock := newActivityClock()
				expired := make(chan struct{})
				clock.startIdleTimer(idle, func() { close(expired) }, nil)
				defer clock.stop()
				done := make(chan error, 1)
				go func() {
					done <- p.sendDatagram(t.Context(), PolicyInput, 1, clock, func() (int, error) {
						t.Error("discarded datagram reached the writer")
						return 1, nil
					}, schedulerIPv4)
				}()
				synctest.Wait()
				time.Sleep(idle * 2)
				synctest.Wait()
				schedulerNoEvent(t, expired, "expiry with work still queued")
				if action == "rule replacement" {
					candidate := schedulerCompile(t, schedulerDropRules, schedulerAcceptRules, limit, PolicyLimit{})
					if err := p.Commit(candidate); err != nil {
						t.Fatal(err)
					}
				} else {
					p.Close()
				}
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				if err := schedulerEvent(t, done, "datagram dropped from queue"); !errors.Is(err, ErrPolicyDenied) {
					t.Errorf("dropped datagram = %v, want %v", err, ErrPolicyDenied)
				}
				schedulerEvent(t, expired, "expiry after queued datagram was dropped")
			})
		})
	}
}

func TestNATPolicySendCancellationWaitsForDispatchedWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		started, done := make(chan struct{}), make(chan error, 1)
		go func() {
			done <- p.Send(ctx, PolicyInput, 1, func() error {
				return policyWrite(a, func() error {
					close(started)
					_, err := a.Write([]byte{1})
					return err
				})
			}, schedulerIPv4)
		}()
		<-started
		cancel()
		synctest.Wait()
		schedulerNoEvent(t, done, "Send while callback still owns its buffer")
		var out [1]byte
		if _, err := io.ReadFull(b, out[:]); err != nil || out[0] != 1 {
			t.Fatalf("read dispatched byte = %v, %v", out, err)
		}
		synctest.Wait()
		if err := schedulerEvent(t, done, "Send after callback releases its buffer"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNATPolicyCommitRejectsLateDial(t *testing.T) {
	ctx := testContext(t)
	p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
	candidate := schedulerCompile(t, schedulerDropRules, schedulerAcceptRules, PolicyLimit{}, PolicyLimit{})
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	deadline, _ := ctx.Deadline()
	if err := peer.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	finish := pinPolicyCommit(t, ctx, p, candidate, conn)
	finish()
	var b [1]byte
	if n, err := peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read from late dial's peer = %d, %v; want 0, EOF", n, err)
	}
}

func TestNATPolicyCommitSettlesBlockedWrite(t *testing.T) {
	p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	started, settled, result := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		result <- p.Send(t.Context(), PolicyInput, 1, func() error {
			defer close(settled)
			return policyWrite(a, func() error {
				close(started)
				_, err := a.Write([]byte{1})
				return err
			})
		}, schedulerIPv4)
	}()
	awaitSchedulerEvent(t, ctx, started, "start pinned write")
	candidate := schedulerCompile(t, schedulerDropRules, schedulerAcceptRules, PolicyLimit{}, PolicyLimit{})
	committed := make(chan error, 1)
	go func() { committed <- p.Commit(candidate) }()
	select {
	case err := <-committed:
		if err != nil {
			t.Fatal(err)
		}
		schedulerEvent(t, settled, "pinned write before replacement")
	case <-ctx.Done():
		t.Fatal("blocked writer prevented policy commit")
	}
	select {
	case err := <-result:
		if !isTimeout(err) {
			t.Errorf("blocked write = %v, want timeout", err)
		}
	case <-ctx.Done():
		t.Fatal("blocked writer did not release Send")
	}
}

func TestNATPolicyCopyStreamBackpressuresAndSplitsWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const burst = 65537
		p := schedulerPolicy(t, PolicyLimit{RateBPS: 8 * burst, BurstBytes: burst, QueueBytes: burst}, PolicyLimit{})
		src, source := net.Pipe()
		dst, destination := net.Pipe()
		defer src.Close()
		defer source.Close()
		defer dst.Close()
		defer destination.Close()
		payload := bytes.Repeat([]byte("abcd"), 20000)
		copyDone, sourceDone, destinationDone := make(chan error, 1), make(chan error, 1), make(chan error, 1)
		got := make([]byte, len(payload))
		go func() { copyDone <- p.CopyStream(t.Context(), PolicyInput, dst, src, schedulerIPv4) }()
		go func() {
			_, err := source.Write(payload)
			sourceDone <- errors.Join(err, source.Close())
		}()
		go func() {
			_, err := io.ReadFull(destination, got)
			destinationDone <- err
		}()
		synctest.Wait()
		schedulerNoEvent(t, sourceDone, "source write before stream earns credit")
		schedulerNoEvent(t, destinationDone, "delivery larger than burst at time zero")
		time.Sleep(2 * time.Second)
		synctest.Wait()
		for name, done := range map[string]<-chan error{"source write": sourceDone, "stream copy": copyDone, "destination read": destinationDone} {
			if err := schedulerEvent(t, done, name); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		if !bytes.Equal(got, payload) {
			t.Error("stream did not deliver every byte in order")
		}
	})
}

func TestNATPolicyCopyStreamRetriesOnlyUnwrittenBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
		src, source := net.Pipe()
		dst, destination := net.Pipe()
		defer src.Close()
		defer source.Close()
		defer dst.Close()
		defer destination.Close()
		copyDone, sourceDone := make(chan error, 1), make(chan error, 1)
		go func() { copyDone <- p.CopyStream(t.Context(), PolicyInput, dst, src, schedulerIPv4) }()
		go func() {
			_, err := source.Write([]byte("abcdef"))
			sourceDone <- errors.Join(err, source.Close())
		}()
		ioCtx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		deadline, _ := ioCtx.Deadline()
		if err := destination.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		var got [6]byte
		if _, err := io.ReadFull(destination, got[:2]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * policyWriteTimeout)
		if _, err := io.ReadFull(destination, got[2:]); err != nil || string(got[:]) != "abcdef" {
			t.Fatalf("read after partial timeout = %q, %v, want abcdef", got[:], err)
		}
		synctest.Wait()
		if err := schedulerEvent(t, sourceDone, "source write"); err != nil {
			t.Error(err)
		}
		if err := schedulerEvent(t, copyDone, "copy after partial timeout"); err != nil {
			t.Error(err)
		}
	})
}

func TestNATPolicyCopyStreamWakesAnIdleDeniedDirection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
		src, source := net.Pipe()
		dst, destination := net.Pipe()
		defer src.Close()
		defer source.Close()
		defer dst.Close()
		defer destination.Close()
		done := make(chan error, 1)
		go func() { done <- p.CopyStream(t.Context(), PolicyInput, dst, src, schedulerIPv4) }()
		synctest.Wait()
		schedulerNoEvent(t, done, "idle stream under allowing policy")
		candidate := schedulerCompile(t, schedulerDropRules, schedulerAcceptRules, PolicyLimit{}, PolicyLimit{})
		if err := p.Commit(candidate); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := schedulerEvent(t, done, "idle stream denied by replacement"); !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("CopyStream = %v, want %v", err, ErrPolicyDenied)
		}
	})
}

func TestNATPolicyIdleStreamLeavesQueueAvailableAndStopsReadingWhenFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		limit := schedulerLimit(8)
		p := schedulerPolicy(t, limit, PolicyLimit{})
		src, source := net.Pipe()
		dst, destination := net.Pipe()
		defer src.Close()
		defer source.Close()
		defer dst.Close()
		defer destination.Close()
		copyDone, writeDone := make(chan error, 1), make(chan error, 1)
		go func() { copyDone <- p.CopyStream(t.Context(), PolicyInput, dst, src, schedulerIPv4) }()
		synctest.Wait()
		if !p.Enqueue(PolicyInput, limit.QueueBytes, func() {}, nil, schedulerIPv4) {
			t.Fatal("idle stream occupied directional queue capacity")
		}
		go func() {
			_, err := source.Write([]byte("ab"))
			writeDone <- err
		}()
		synctest.Wait()
		schedulerNoEvent(t, writeDone, "two-byte source write while the queue is full")
		p.Close()
		if err := <-copyDone; !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("closing stream = %v, want %v", err, ErrPolicyDenied)
		}
		if err := src.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-writeDone; !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("blocked source write = %v, want %v", err, io.ErrClosedPipe)
		}
	})
}

type schedulerPausedConn struct {
	net.Conn
	waiting chan struct{}
	resumed chan struct{}
}

func (c schedulerPausedConn) Write(b []byte) (int, error) {
	select {
	case <-c.resumed:
		return c.Conn.Write(b)
	default:
		return 0, errPolicyHandoffPaused
	}
}

func (c schedulerPausedConn) waitPolicyWrite(ctx context.Context) error {
	close(c.waiting)
	select {
	case <-c.resumed:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func TestNATPolicyCopyStreamWaitsOutsideGateDuringCheckpoint(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := schedulerPolicy(t, PolicyLimit{}, PolicyLimit{})
		src, source := net.Pipe()
		dst, destination := net.Pipe()
		defer src.Close()
		defer source.Close()
		defer dst.Close()
		defer destination.Close()
		paused := schedulerPausedConn{Conn: dst, waiting: make(chan struct{}), resumed: make(chan struct{})}
		copyDone, writeDone := make(chan error, 1), make(chan error, 1)
		go func() { copyDone <- p.CopyStream(t.Context(), PolicyInput, paused, src, schedulerIPv4) }()
		go func() {
			_, err := source.Write([]byte("abc"))
			writeDone <- errors.Join(err, source.Close())
		}()
		synctest.Wait()
		schedulerEvent(t, paused.waiting, "stream waiting for checkpoint resume")
		candidate := schedulerCompile(t, schedulerAcceptRules, schedulerDropRules, PolicyLimit{}, PolicyLimit{})
		if err := p.Commit(candidate); err != nil {
			t.Fatal(err)
		}
		close(paused.resumed)
		var got [3]byte
		if _, err := io.ReadFull(destination, got[:]); err != nil || string(got[:]) != "abc" {
			t.Fatalf("read after resume = %q, %v, want abc", got[:], err)
		}
		if err := <-copyDone; err != nil {
			t.Errorf("CopyStream after resume: %v", err)
		}
		if err := <-writeDone; err != nil {
			t.Errorf("source write: %v", err)
		}
	})
}
