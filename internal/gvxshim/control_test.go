package gvxshim

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestAttachedInstanceOutlivesHandoffDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newControlState(time.Now().Add(time.Second), time.Second)
		if err := state.Attach(); err != nil {
			t.Fatal(err)
		}
		<-time.After(2 * time.Second)
		state.expireHandoff()
		if err := state.Attach(); err != nil {
			t.Fatalf("attached instance expired: %v", err)
		}
		if state.Stopping() {
			t.Fatal("attached instance stopped at handoff deadline")
		}
	})
}

func TestExpiredHandoffCannotAttach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newControlState(time.Now().Add(time.Second), time.Second)
		<-time.After(time.Second)
		if err := state.Attach(); !errors.Is(err, errHandoffExpired) {
			t.Fatalf("Attach = %v, want expired handoff", err)
		}
		select {
		case <-state.StopRequested():
		default:
			t.Fatal("expired handoff did not request stop")
		}
		select {
		case <-state.Attached():
			t.Fatal("expired handoff attached")
		default:
		}
	})
}

func TestRepeatedStopPreservesDrainDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newControlState(time.Now().Add(time.Minute), 10*time.Second)
		if err := state.BeginRPCStop(); err != nil {
			t.Fatal(err)
		}
		first, ok := state.DrainDeadline()
		if !ok {
			t.Fatal("stop has no drain deadline")
		}
		<-time.After(time.Second)
		state.RequestStop()
		if err := state.BeginRPCStop(); err != nil {
			t.Fatal(err)
		}
		second, _ := state.DrainDeadline()
		if !first.Equal(second) {
			t.Fatalf("repeated stop changed deadline: %v to %v", first, second)
		}
		if err := state.Attach(); !errors.Is(err, errStopping) {
			t.Fatalf("Attach after stop = %v", err)
		}
	})
}

func TestShutdownBarrierWaitsForEveryRegisteredReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newControlState(time.Now().Add(time.Minute), time.Second)
		for range 2 {
			if err := state.BeginRPCStop(); err != nil {
				t.Fatal(err)
			}
		}
		sealed := make(chan error, 1)
		go func() { sealed <- state.WaitAndSeal(t.Context()) }()
		if err := state.ReplyWritten(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case err := <-sealed:
			t.Fatalf("barrier crossed with one pending reply: %v", err)
		default:
		}
		if err := state.ReplyWritten(); err != nil {
			t.Fatal(err)
		}
		if err := <-sealed; err != nil {
			t.Fatal(err)
		}
		if err := state.BeginRPCStop(); !errors.Is(err, errStopping) {
			t.Fatalf("sealed registration = %v", err)
		}
		if err := state.ReplyWritten(); !errors.Is(err, errReplyUnregistered) {
			t.Fatalf("extra reply = %v", err)
		}
	})
}

func TestShutdownBarrierExpiresWithPendingReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		state := newControlState(time.Now().Add(time.Minute), time.Second)
		if err := state.BeginRPCStop(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := state.WaitAndSeal(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("pending reply barrier = %v", err)
		}
	})
}

func TestReplyRegistrationRacesAtomicSealing(t *testing.T) {
	for range 100 {
		state := newControlState(time.Now().Add(time.Minute), time.Second)
		state.RequestStop()
		gate := make(chan struct{})
		registered := make(chan error, 1)
		sealed := make(chan error, 1)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() { defer workers.Done(); <-gate; registered <- state.BeginRPCStop() }()
		go func() { defer workers.Done(); <-gate; sealed <- state.WaitAndSeal(t.Context()) }()
		close(gate)
		err := <-registered
		if err == nil {
			if err := state.ReplyWritten(); err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, errStopping) {
			t.Fatal(err)
		}
		if err := <-sealed; err != nil {
			t.Fatal(err)
		}
		workers.Wait()
		if err := state.BeginRPCStop(); !errors.Is(err, errStopping) {
			t.Fatalf("post-barrier registration = %v", err)
		}
	}
}
