package gvxshim

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	sandbox "github.com/containerd/containerd/api/runtime/sandbox/v1"
	task "github.com/containerd/containerd/api/runtime/task/v3"
	"github.com/containerd/ttrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type queuedListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func newQueuedListener() *queuedListener {
	return &queuedListener{connections: make(chan net.Conn, 64), done: make(chan struct{})}
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn := <-l.connections:
		return conn, nil
	}
}
func (l *queuedListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *queuedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

type controlledWriter struct {
	net.Conn
	write func([]byte) (int, error)
}

func (c *controlledWriter) Write(p []byte) (int, error) { return c.write(p) }

func barrierTransport(t *testing.T, write func([]byte) (int, error)) (*taskTransport, net.Conn, *controlState) {
	t.Helper()
	state := newControlState(time.Now().Add(time.Minute), time.Second)
	listener := newQueuedListener()
	raw, peer := net.Pipe()
	listener.connections <- &controlledWriter{Conn: raw, write: write}
	transport := newTaskTransport(listener, state)
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
		if err := transport.CloseConnections(); err != nil {
			t.Errorf("close raw transport: %v", err)
		}
		if err := peer.Close(); err != nil {
			t.Errorf("close peer: %v", err)
		}
	})
	conn, err := transport.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return transport, conn, state
}

func responseFrame(stream uint32, payload []byte) []byte {
	frame := make([]byte, 10+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(frame[4:8], stream)
	frame[8] = 0x02
	copy(frame[10:], payload)
	return frame
}

func requirePendingReply(t *testing.T, state *controlState) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := state.WaitAndSeal(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("response barrier = %v, want pending response debt", err)
	}
}

func replyTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestFragmentedResponseDischargesOnlyAfterFinalAcceptedByte(t *testing.T) {
	var accepted bytes.Buffer
	_, conn, state := barrierTransport(t, accepted.Write)
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	frame := responseFrame(1, nil)
	for _, part := range [][]byte{frame[:3], frame[3:9]} {
		if _, err := conn.Write(part); err != nil {
			t.Fatal(err)
		}
		requirePendingReply(t, state)
	}
	if _, err := conn.Write(frame[9:]); err != nil {
		t.Fatal(err)
	}
	if err := state.WaitAndSeal(replyTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(accepted.Bytes(), frame) {
		t.Fatalf("accepted bytes = %x, want complete response %x", accepted.Bytes(), frame)
	}
}

func TestPartialUnderlyingWriteDoesNotDischargeUnwrittenHeader(t *testing.T) {
	var accepted bytes.Buffer
	first := true
	_, conn, state := barrierTransport(t, func(p []byte) (int, error) {
		if first {
			first = false
			accepted.Write(p[:9])
			return 9, io.ErrUnexpectedEOF
		}
		return accepted.Write(p)
	})
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	frame := responseFrame(1, nil)
	if n, err := conn.Write(frame); n != 9 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial Write = %d, %v, want 9, unexpected EOF", n, err)
	}
	requirePendingReply(t, state)
	if _, err := conn.Write(frame[9:]); err != nil {
		t.Fatal(err)
	}
	if err := state.WaitAndSeal(replyTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if accepted.Len() != len(frame) {
		t.Fatalf("accepted bytes = %d, want %d", accepted.Len(), len(frame))
	}
}

func TestNonemptyResponseBodyCannotDischargeShutdownDebt(t *testing.T) {
	_, conn, state := barrierTransport(t, func(p []byte) (int, error) { return len(p), nil })
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	body := responseFrame(3, nil)
	frame := responseFrame(1, body)
	for _, part := range [][]byte{frame[:12], frame[12:]} {
		if _, err := conn.Write(part); err != nil {
			t.Fatal(err)
		}
		requirePendingReply(t, state)
	}
	if _, err := conn.Write(responseFrame(3, nil)); err != nil {
		t.Fatal(err)
	}
	if err := state.WaitAndSeal(replyTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestOneWriteDischargesEachCompletedShutdownResponse(t *testing.T) {
	_, conn, state := barrierTransport(t, func(p []byte) (int, error) { return len(p), nil })
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	frames := append(responseFrame(1, nil), responseFrame(3, nil)...)
	if _, err := conn.Write(frames[:19]); err != nil {
		t.Fatal(err)
	}
	requirePendingReply(t, state)
	if _, err := conn.Write(frames[19:]); err != nil {
		t.Fatal(err)
	}
	if err := state.WaitAndSeal(replyTestContext(t)); err != nil {
		t.Fatal(err)
	}
	if err := state.BeginRPCStop(); err == nil {
		t.Fatal("sealed barrier accepted another successful response")
	}
}

func TestInvalidFrameCannotResynchronizeAndDischargeDebt(t *testing.T) {
	for _, name := range []string{"flags", "type", "length", "stream"} {
		t.Run(name, func(t *testing.T) {
			_, conn, state := barrierTransport(t, func(p []byte) (int, error) { return len(p), nil })
			if err := state.BeginRPCStop(); err != nil {
				t.Fatal(err)
			}
			frame := responseFrame(1, nil)
			switch name {
			case "flags":
				frame[9] = 1
			case "type":
				frame[8] = 3
			case "length":
				binary.BigEndian.PutUint32(frame[:4], 4<<20+1)
			case "stream":
				binary.BigEndian.PutUint32(frame[4:8], 2)
			}
			if _, err := conn.Write(frame); !errors.Is(err, errInvalidTaskFrame) {
				t.Fatalf("invalid frame error = %v", err)
			}
			if _, err := conn.Write(responseFrame(3, nil)); !errors.Is(err, errInvalidTaskFrame) {
				t.Fatalf("poisoned frame error = %v", err)
			}
			requirePendingReply(t, state)
		})
	}
}

func TestUnsolicitedEmptyReplyRequestsStop(t *testing.T) {
	_, conn, state := barrierTransport(t, func(p []byte) (int, error) { return len(p), nil })
	if _, err := conn.Write(responseFrame(1, nil)); err == nil {
		t.Fatal("empty success without shutdown obligation returned nil")
	}
	select {
	case <-state.StopRequested():
	default:
		t.Fatal("reply invariant failure did not request stop")
	}
}

func TestDirectRawClosureInterruptsNonreadingAcceptedTransport(t *testing.T) {
	ctx := replyTestContext(t)
	state := newControlState(time.Now().Add(time.Minute), time.Second)
	listener := newQueuedListener()
	raw, peer := net.Pipe()
	defer peer.Close()
	entered := make(chan struct{})
	listener.connections <- &controlledWriter{Conn: raw, write: func(p []byte) (int, error) {
		close(entered)
		return raw.Write(p)
	}}
	transport := newTaskTransport(listener, state)
	t.Cleanup(func() { transport.Close(); transport.CloseConnections() })
	conn, err := transport.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := conn.Write(responseFrame(1, nil))
		written <- err
	}()
	t.Cleanup(func() {
		if err := transport.CloseConnections(); err != nil {
			t.Errorf("close blocked transport: %v", err)
		}
		select {
		case <-finished:
		case <-ctx.Done():
			t.Error("blocked writer did not exit")
		}
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("writer did not enter raw Write")
	}
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		t.Fatalf("listener closure interrupted accepted connection: %v", err)
	default:
	}
	if err := transport.CloseConnections(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("nonreading transport completed response after direct closure")
		}
	case <-ctx.Done():
		t.Fatal("direct close did not interrupt raw Write")
	}
	requirePendingReply(t, state)
}

func TestShutdownEnvelopeInvariantUsesPublicProtobuf(t *testing.T) {
	for _, message := range []proto.Message{&emptypb.Empty{}, &sandbox.ShutdownSandboxResponse{}} {
		payload, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := proto.Marshal(&ttrpc.Response{Status: status.Convert(nil).Proto(), Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope) != 0 {
			t.Fatalf("shutdown envelope %T = %x, want zero bytes", message, envelope)
		}
	}
	connect, err := proto.Marshal(&task.ConnectResponse{ShimPid: 1, Version: "gvx-control-v1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range []*ttrpc.Response{
		{Payload: connect},
		{Status: status.New(codes.Unimplemented, "unsupported").Proto()},
	} {
		envelope, err := proto.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		if len(envelope) == 0 {
			t.Fatal("non-shutdown response produced counted empty envelope")
		}
	}
}

func TestAcceptedConnectionLimitRejectsExcessWithoutClosingOthers(t *testing.T) {
	ctx := replyTestContext(t)
	state := newControlState(time.Now().Add(time.Minute), time.Second)
	listener := newQueuedListener()
	transport := newTaskTransport(listener, state)
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
		if err := transport.CloseConnections(); err != nil {
			t.Errorf("close accepted connections: %v", err)
		}
	})
	var first net.Conn
	for range 32 {
		raw, peer := net.Pipe()
		t.Cleanup(func() { peer.Close() })
		listener.connections <- raw
		accepted, err := transport.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = accepted
		}
	}
	excess, rejectedPeer := net.Pipe()
	defer rejectedPeer.Close()
	if err := rejectedPeer.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	listener.connections <- excess
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	result := make(chan acceptResult, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := transport.Accept()
		result <- acceptResult{conn, err}
	}()
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
		select {
		case <-finished:
		case <-ctx.Done():
			t.Error("connection-limit accept worker did not exit")
		}
	})
	var b [1]byte
	if _, err := rejectedPeer.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("excess connection read = %v, want EOF", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, replacementPeer := net.Pipe()
	defer replacement.Close()
	defer replacementPeer.Close()
	listener.connections <- replacement
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("accept after slot release: %v", got.err)
		}
		if err := got.conn.Close(); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("accept did not resume after slot release")
	}
}

func TestFailedWriteCannotDischargeUnacceptedResponse(t *testing.T) {
	_, conn, state := barrierTransport(t, func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := state.BeginRPCStop(); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(responseFrame(1, nil)); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failed Write = %d, %v, want 0, closed pipe", n, err)
	}
	requirePendingReply(t, state)
}
