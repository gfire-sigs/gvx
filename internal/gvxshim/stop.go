package gvxshim

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	taskv2 "github.com/containerd/containerd/api/runtime/task/v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type stopServer struct {
	listener    net.Listener
	state       *controlState
	timeout     time.Duration
	token       [32]byte
	mu          sync.Mutex
	connections map[net.Conn]time.Time
	workers     sync.WaitGroup
	accepted    chan struct{}
	draining    chan struct{}
}

func newStopServer(listener net.Listener, state *controlState, token [32]byte, timeout time.Duration) *stopServer {
	s := &stopServer{listener: listener, state: state, token: token, timeout: timeout, connections: make(map[net.Conn]time.Time), accepted: make(chan struct{}), draining: make(chan struct{})}
	go s.accept()
	go func() {
		defer close(s.draining)
		<-state.StopRequested()
		_ = listener.Close()
		deadline, _ := state.DrainDeadline()
		s.mu.Lock()
		for conn, acceptedDeadline := range s.connections {
			if deadline.Before(acceptedDeadline) {
				_ = conn.SetDeadline(deadline)
			}
		}
		s.mu.Unlock()
	}()
	return s
}

func (s *stopServer) accept() {
	defer close(s.accepted)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !s.state.Stopping() {
				s.state.RequestStop()
			}
			return
		}
		deadline := time.Now().Add(s.timeout)
		if drain, stopping := s.state.DrainDeadline(); stopping && drain.Before(deadline) {
			deadline = drain
		}
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			continue
		}
		s.mu.Lock()
		if len(s.connections) >= 8 {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		if drain, stopping := s.state.DrainDeadline(); stopping && drain.Before(deadline) {
			deadline = drain
			if err := conn.SetDeadline(deadline); err != nil {
				s.mu.Unlock()
				conn.Close()
				continue
			}
		}
		s.connections[conn] = deadline
		s.workers.Add(1)
		s.mu.Unlock()
		go s.respond(conn)
	}
}

func (s *stopServer) respond(conn net.Conn) {
	defer s.workers.Done()
	defer func() { conn.Close(); s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	var token [32]byte
	if _, err := io.ReadFull(conn, token[:]); err != nil {
		return
	}
	accepted := byte(0)
	if subtle.ConstantTimeCompare(token[:], s.token[:]) == 1 {
		s.state.RequestStop()
		accepted = 1
	}
	_, _ = conn.Write([]byte{accepted})
}

func (s *stopServer) close(ctx context.Context) error {
	err := s.listener.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	<-s.accepted
	<-s.draining
	deadline, _ := ctx.Deadline()
	s.mu.Lock()
	for conn, acceptedDeadline := range s.connections {
		if deadline.Before(acceptedDeadline) {
			_ = conn.SetDeadline(deadline)
		}
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.workers.Wait(); close(done) }()
	select {
	case <-done:
		return err
	case <-ctx.Done():
		s.mu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.mu.Unlock()
		<-done
		return errors.Join(err, ctx.Err())
	}
}

func requestIndependentStop(ctx context.Context, record *stateRecord) error {
	token, err := decodeGeneration(record.Generation)
	if err != nil {
		return err
	}
	conn, err := dialLocal(ctx, record.Stop.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		return errInvalidState
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if err := writeAll(conn, token[:]); err != nil {
		return err
	}
	var acknowledgment [1]byte
	if _, err := io.ReadFull(conn, acknowledgment[:]); err != nil {
		return err
	}
	if acknowledgment[0] != 1 {
		return errConflict
	}
	return nil
}

func requireAbsent(dir *pinnedDir, name string) error {
	if dir == nil {
		return nil
	}
	_, err := dir.Root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected %s: %w", name, errConflict)
}

func cleanTransient(paths *instancePaths, record *stateRecord, recordFile *ownedEntry) error {
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return err
	}
	if record == nil {
		return errors.Join(requireAbsent(paths.State, "diagnostics.log"), requireAbsent(paths.State, "state.json"), absentEndpoints(paths))
	}
	var result error
	for _, endpoint := range []endpointRef{record.Task, record.Stop} {
		if endpoint.Socket == nil {
			if paths.UnixEndpointDir != nil {
				name := "task"
				if endpoint.Address == paths.StopAddress {
					name = "stop"
				}
				result = errors.Join(result, requireAbsent(paths.UnixEndpointDir, name))
			}
			continue
		}
		if paths.UnixEndpointDir != nil {
			result = errors.Join(result, removeOwned(paths.UnixEndpointDir, *endpoint.Socket))
		}
	}
	result = errors.Join(result, removeOwned(paths.State, record.Log))
	if result != nil {
		return result
	}
	if record.Paths.UnixEndpointDir != nil {
		if paths.UnixEndpointDir != nil {
			if err := removeEndpointDir(paths, *record.Paths.UnixEndpointDir); err != nil {
				return err
			}
		}
	}
	if recordFile != nil {
		return removeOwned(paths.State, *recordFile)
	}
	return nil
}

func deleteInstance(ctx context.Context, admission *deleteAdmission) (response *taskv2.DeleteResponse, result error) {
	paths := admission.Paths
	if paths.State == nil {
		if err := revalidateAdmission(admission); err != nil {
			return nil, err
		}
		if err := cleanTransient(paths, nil, nil); err != nil {
			return nil, err
		}
		return cleanupResponse(), nil
	}
	command, err := openLock(paths, commandLock)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, command.Close()) }()
	if err := lock(ctx, command); err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, unlock(command)) }()
	if err := revalidateAdmission(admission); err != nil {
		return nil, err
	}
	lease, err := openLock(paths, lifetimeLease)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
	err = tryLock(lease)
	if errors.Is(err, errLockBusy) {
		if admission.Record == nil {
			return nil, errConflict
		}
		stopErr := requestIndependentStop(ctx, admission.Record)
		if err := lock(ctx, lease); err != nil {
			return nil, errors.Join(err, stopErr)
		}
	} else if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, unlock(lease)) }()
	if err := revalidateAdmission(admission); err != nil {
		return nil, err
	}
	if err := cleanTransient(paths, admission.Record, admission.RecordFile); err != nil {
		return nil, err
	}
	return cleanupResponse(), nil
}

func cleanupResponse() *taskv2.DeleteResponse {
	return &taskv2.DeleteResponse{Pid: 0, ExitStatus: 0, ExitedAt: timestamppb.Now()}
}
