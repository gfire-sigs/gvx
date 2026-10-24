package gvxshim

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

type windowsLogSink struct {
	mu          sync.Mutex
	listener    net.Listener
	connection  net.Conn
	diagnostics *os.File
	timeout     time.Duration
	closed      bool
	done        chan struct{}
	closeOnce   sync.Once
	readers     sync.WaitGroup
	closeErr    error
}

func openLog(ctx context.Context, paths *instancePaths, diagnostics ownedEntry, writeTimeout time.Duration) (logOutput, error) {
	if writeTimeout <= 0 {
		return logOutput{}, errUnsafeEntry
	}
	file, err := openDiagnostics(paths, diagnostics)
	if err != nil {
		return logOutput{}, err
	}
	address := `\\.\pipe\containerd-shim-` + paths.Identity.Namespace + "-" + paths.Identity.ID + "-log"
	listener, err := listenProtectedPipe(address)
	if err != nil {
		return logOutput{}, errors.Join(err, file.Close())
	}
	s := &windowsLogSink{listener: listener, diagnostics: file, timeout: writeTimeout, done: make(chan struct{})}
	go s.accept()
	return startBoundedLog(ctx, s), nil
}

func (s *windowsLogSink) accept() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		if s.connection != nil {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.connection = conn
		s.mu.Unlock()
		s.readers.Add(1)
		go func() {
			defer s.readers.Done()
			var unexpected [1]byte
			conn.Read(unexpected[:])
			s.mu.Lock()
			if s.connection == conn {
				s.connection = nil
			}
			s.mu.Unlock()
			conn.Close()
		}()
	}
}

func (s *windowsLogSink) Write(data []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, os.ErrClosed
	}
	conn := s.connection
	file := s.diagnostics
	s.mu.Unlock()
	if conn == nil {
		return file.Write(data)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return 0, err
	}
	n, err := conn.Write(data)
	if err == nil {
		return n, nil
	}
	s.mu.Lock()
	if s.connection == conn {
		s.connection = nil
	}
	s.mu.Unlock()
	closeErr := conn.Close()
	// Preserve diagnostics when the containerd reader disconnects or stops reading.
	fallbackN, fallbackErr := file.Write(data)
	if fallbackErr == nil {
		return fallbackN, nil
	}
	return n, errors.Join(err, closeErr, fallbackErr)
}

func (s *windowsLogSink) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		conn := s.connection
		s.connection = nil
		s.mu.Unlock()
		listenerErr := s.listener.Close()
		var connErr error
		if conn != nil {
			connErr = conn.Close()
		}
		s.closeErr = errors.Join(listenerErr, connErr, s.diagnostics.Close())
	})
	<-s.done
	s.readers.Wait()
	return s.closeErr
}
