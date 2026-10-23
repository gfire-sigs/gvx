package whpx

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunTransportRoutesConcurrentProcessors(t *testing.T) {
	server, connection := net.Pipe()
	started := make(chan uint32, 2)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveRuns(server, func(request runRequest, exit []byte) error {
			index := request.index
			started <- index
			<-release
			binary.LittleEndian.PutUint32(exit, index+100)
			return nil
		}, func() error { return nil })
	}()
	client := newRunClient(connection)
	results := make(chan error, 2)
	for _, index := range []uint32{0, maxVPs - 1} {
		go func() {
			exit := make([]byte, exitCtxBufSize)
			if err := client.run(index, exit); err != nil {
				results <- err
				return
			}
			if got := binary.LittleEndian.Uint32(exit); got != index+100 {
				results <- errors.New("response belongs to another processor")
				return
			}
			results <- nil
		}()
	}
	first, second := <-started, <-started
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Error(err)
	}
	if first == second {
		t.Errorf("both processors used index %d", first)
	}
}

func TestRunTransportAppliesPreparedResumeOnce(t *testing.T) {
	server, connection := net.Pipe()
	requests := make(chan runRequest, 2)
	done := make(chan error, 1)
	go func() {
		done <- serveRuns(server, func(request runRequest, _ []byte) error {
			requests <- request
			return nil
		}, func() error { return nil })
	}()
	client := newRunClient(connection)
	if err := client.prepareResumePC(0, 0x400000); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := client.run(0, make([]byte, exitCtxBufSize)); err != nil {
			t.Error(err)
		}
	}
	first, second := <-requests, <-requests
	if !first.setPC || first.resumePC != 0x400000 || second.setPC {
		t.Errorf("resume requests: first=%+v second=%+v", first, second)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Error(err)
	}
}

type readSignalConn struct {
	net.Conn
	once    sync.Once
	started chan struct{}
}

func (c *readSignalConn) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Read(data)
}

func TestRunTransportDoesNotDelayOtherProcessorBehindBlockedRun(t *testing.T) {
	server, connection := net.Pipe()
	reading := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveRuns(server, func(request runRequest, _ []byte) error {
			if request.index == 0 {
				<-release
			}
			return nil
		}, func() error { return nil })
	}()
	client := newRunClient(&readSignalConn{Conn: connection, started: reading})
	slow := make(chan error, 1)
	fast := make(chan error, 1)
	go func() { slow <- client.run(0, make([]byte, exitCtxBufSize)) }()
	<-reading
	go func() { fast <- client.run(1, make([]byte, exitCtxBufSize)) }()
	select {
	case err := <-fast:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Error("processor 1 waited for processor 0")
	}
	close(release)
	if err := <-slow; err != nil {
		t.Error(err)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Error(err)
	}
}

func TestRunTransportPreservesErrorsAndResumes(t *testing.T) {
	server, connection := net.Pipe()
	done := make(chan error, 1)
	calls := 0
	go func() {
		done <- serveRuns(server, func(_ runRequest, exit []byte) error {
			calls++
			if calls == 1 {
				return errors.New("processor is not created")
			}
			exit[0] = 42
			return nil
		}, func() error { return nil })
	}()
	client := newRunClient(connection)
	exit := make([]byte, exitCtxBufSize)
	if err := client.run(0, exit); err == nil || err.Error() != "processor is not created" {
		t.Errorf("run error = %v", err)
	}
	if err := client.run(0, exit); err != nil || exit[0] != 42 {
		t.Errorf("next run = %v, exit byte = %d", err, exit[0])
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Error(err)
	}
}

func TestRunTransportRejectsMalformedRequest(t *testing.T) {
	for _, scenario := range []string{"processor", "flags", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			server, connection := net.Pipe()
			done := make(chan error, 1)
			go func() {
				done <- serveRuns(server, func(runRequest, []byte) error {
					t.Error("malformed request reached the backend")
					return nil
				}, func() error { return nil })
			}()
			var request [16]byte
			switch scenario {
			case "processor":
				binary.LittleEndian.PutUint32(request[:], maxVPs)
			case "flags":
				binary.LittleEndian.PutUint32(request[4:8], 2)
			case "truncated":
				_, _ = connection.Write(request[:7])
				_ = connection.Close()
			}
			if scenario != "truncated" {
				_, _ = connection.Write(request[:])
			}
			if err := <-done; err == nil {
				t.Error("malformed request did not close the transport")
			}
			_ = connection.Close()
		})
	}
}

func TestRunTransportStopsPendingProcessorOnDisconnect(t *testing.T) {
	server, connection := net.Pipe()
	started := make(chan struct{})
	stopped := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveRuns(server, func(runRequest, []byte) error {
			close(started)
			<-stopped
			return errors.New("processor stopped")
		}, func() error { close(stopped); return nil })
	}()
	client := newRunClient(connection)
	result := make(chan error, 1)
	go func() { result <- client.run(0, make([]byte, exitCtxBufSize)) }()
	<-started
	_ = client.Close()
	if err := <-result; err == nil {
		t.Error("disconnected run reported success")
	}
	if err := <-done; err != nil {
		t.Error(err)
	}
}

func TestRunTransportRejectsDuplicatePendingProcessor(t *testing.T) {
	server, connection := net.Pipe()
	started := make(chan struct{})
	stopped := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveRuns(server, func(runRequest, []byte) error {
			close(started)
			<-stopped
			return nil
		}, func() error { close(stopped); return nil })
	}()
	var request [16]byte
	_, _ = connection.Write(request[:])
	<-started
	_, _ = connection.Write(request[:])
	if err := <-done; err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate request returned %v", err)
	}
	_ = connection.Close()
}

func TestRunClientRejectsMalformedReply(t *testing.T) {
	for _, scenario := range []string{"processor", "unexpected processor", "error length", "truncated"} {
		t.Run(scenario, func(t *testing.T) {
			server, connection := net.Pipe()
			client := newRunClient(connection)
			var writer sync.WaitGroup
			writer.Go(func() {
				defer server.Close()
				var request [16]byte
				_, _ = io.ReadFull(server, request[:])
				var packet [runReplySize]byte
				switch scenario {
				case "processor":
					binary.LittleEndian.PutUint32(packet[:4], maxVPs)
				case "unexpected processor":
					binary.LittleEndian.PutUint32(packet[:4], 1)
				case "error length":
					binary.LittleEndian.PutUint32(packet[4:8], exitCtxBufSize+1)
				case "truncated":
					_, _ = server.Write(packet[:9])
					return
				}
				_, _ = server.Write(packet[:])
			})
			if err := client.run(0, make([]byte, exitCtxBufSize)); err == nil {
				t.Error("malformed reply reported success")
			}
			_ = client.Close()
			writer.Wait()
		})
	}
}
