package gvxshim

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v3"
)

const processServeGateEnv = "GVX_SHIM_TEST_SERVE_GATE"

// processServeGate delays only the test binary before production Main reads its startup pipes.
// TestMain retains the connection until os.Exit, so peer closure proves that the child actually exited.
func processServeGate() (net.Conn, error) {
	address := os.Getenv(processServeGateEnv)
	if address == "" || len(os.Args) < 2 || os.Args[len(os.Args)-1] != "serve" {
		return nil, nil
	}
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { return nil, errors.Join(err, conn.Close()) }
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fail(err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		return fail(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		return fail(err)
	}
	if ack[0] != 1 {
		return fail(io.ErrUnexpectedEOF)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	return conn, nil
}

func TestProcessAttachedOutlivesHandoffDeadline(t *testing.T) {
	f := newProcessFixture(t)
	f.timeout = 3 * time.Second
	record := f.start()
	lease := holdProcessLease(t, record)
	client, ctx := processClient(t, record)
	assertProcessConnect(t, ctx, client, record)
	leaseCtx, cancel := context.WithTimeout(ctx, f.timeout+time.Second)
	defer cancel()
	if err := lock(leaseCtx, lease); !errors.Is(err, context.DeadlineExceeded) {
		if err == nil {
			if unlockErr := unlock(lease); unlockErr != nil {
				t.Errorf("unlock unexpectedly released child lease: %v", unlockErr)
			}
		}
		t.Fatalf("attached child released its lease across the handoff deadline: %v", err)
	}
	assertProcessConnect(t, ctx, client, record)
	if _, err := task.NewTTRPCTaskClient(client).Shutdown(ctx, &task.ShutdownRequest{ID: f.id}); err != nil {
		t.Fatalf("shutdown attached child after handoff interval: %v", err)
	}
	awaitProcessExit(t, lease, record)
}

func TestProcessLauncherDeathBeforeBoundReport(t *testing.T) {
	f := newProcessFixture(t)
	f.timeout = 3 * time.Second
	// This scenario needs the test-only gate, even when other process tests use an explicit command.
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f.binary = binary
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cmd := f.cmd(ctx, "start")
	cmd.Env = append(cmd.Env, processServeGateEnv+"="+listener.Addr().String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("kill original launcher during recovery cleanup: %v", err)
		}
		<-done
	})
	gate, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("serving child did not reach the pre-Main gate: %v", err)
	}
	defer gate.Close()
	if err := gate.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(gate, signal[:]); err != nil || signal[0] != 1 {
		t.Fatalf("serving child gate handshake=%v, error=%v", signal, err)
	}
	record := readProcessRecord(t, f.bundle)
	if record.Phase != recordPrepared || record.ShimPID != 0 {
		t.Fatalf("launcher published ready state before its child entered Main: phase=%q pid=%d", record.Phase, record.ShimPID)
	}
	lease := holdProcessLease(t, record)
	assertProcessEndpointsAbsent(t, ctx, record.Task.Address, record.Stop.Address)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill original launcher before bound report: %v", err)
	}
	select {
	case err := <-done:
		waited = true
		if err == nil {
			t.Fatal("launcher exited successfully before receiving a bound report")
		}
	case <-ctx.Done():
		t.Fatalf("original launcher did not exit: %v", ctx.Err())
	}
	if stdout.Len() != 0 {
		t.Errorf("launcher emitted bootstrap before its child entered Main: %q", stdout.Bytes())
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		t.Fatalf("release serving child into production Main: %v", err)
	}
	if n, err := gate.Read(signal[:]); n != 0 || !processGatePeerClosed(err) {
		t.Fatalf("child retained its process-owned gate after launcher death: n=%d err=%v", n, err)
	}
	awaitProcessExit(t, lease, record)
}
