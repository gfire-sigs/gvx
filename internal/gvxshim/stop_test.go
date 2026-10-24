package gvxshim

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func lifecycleStopServer(t *testing.T) (*stopServer, *controlState, stateRecord) {
	t.Helper()
	paths, record, _ := lifecyclePrepared(t)
	endpoint, err := listenLocal(t.Context(), paths, stopEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	record.Stop = endpoint.Ref
	token, err := decodeGeneration(record.Generation)
	if err != nil {
		t.Fatal(err)
	}
	state := newControlState(time.Now().Add(time.Minute), time.Second)
	server := newStopServer(endpoint.Listener, state, token, time.Minute)
	t.Cleanup(func() {
		state.RequestStop()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.close(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Error(err)
		}
		if endpoint.Ref.Socket != nil {
			if err := removeOwned(paths.UnixEndpointDir, *endpoint.Ref.Socket); err != nil {
				t.Error(err)
			}
		}
	})
	return server, state, record
}

func stopTestConnection(t *testing.T, address string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := dialLocal(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestStopRejectsWrongGenerationWithoutStopping(t *testing.T) {
	_, state, record := lifecycleStopServer(t)
	conn := stopTestConnection(t, record.Stop.Address)
	var wrong [32]byte
	if err := writeAll(conn, wrong[:]); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 0 {
		t.Fatalf("wrong generation acknowledgment = %d, want 0", reply[0])
	}
	if state.Stopping() {
		t.Fatal("wrong generation stopped the instance")
	}
	if n, err := conn.Read(reply[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("stop connection reused after rejection: n=%d err=%v", n, err)
	}
}

func TestStopAcknowledgesMatchingGeneration(t *testing.T) {
	_, state, record := lifecycleStopServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := requestIndependentStop(ctx, &record); err != nil {
		t.Fatal(err)
	}
	select {
	case <-state.StopRequested():
	default:
		t.Fatal("acknowledged stop did not enter stopping")
	}
	select {
	case <-state.Attached():
		t.Fatal("independent stop incorrectly completed RPC attachment")
	default:
	}
}

func TestStopRejectsExcessConnections(t *testing.T) {
	_, _, record := lifecycleStopServer(t)
	for range 8 {
		conn := stopTestConnection(t, record.Stop.Address)
		if err := writeAll(conn, []byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	excess := stopTestConnection(t, record.Stop.Address)
	var reply [1]byte
	if n, err := excess.Read(reply[:]); n != 0 || err == nil {
		t.Fatalf("excess connection retained: n=%d err=%v", n, err)
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("excess connection was not rejected before its deadline: %v", err)
	}
}
