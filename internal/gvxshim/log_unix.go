//go:build linux || darwin

package gvxshim

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type unixLogSink struct {
	mu          sync.Mutex
	paths       *instancePaths
	diagnostics *os.File
	fifo        *os.File
	fifoID      *fileIdentity
	timeout     time.Duration
	closed      bool
}

func openLog(ctx context.Context, paths *instancePaths, diagnostics ownedEntry, writeTimeout time.Duration) (logOutput, error) {
	if writeTimeout <= 0 {
		return logOutput{}, errUnsafeEntry
	}
	file, err := openDiagnostics(paths, diagnostics)
	if err != nil {
		return logOutput{}, err
	}
	s := &unixLogSink{paths: paths, diagnostics: file, timeout: writeTimeout}
	info, err := paths.Bundle.Root.Lstat("log")
	if err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeNamedPipe == 0 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
			return logOutput{}, errors.Join(errUnsafeEntry, file.Close())
		}
		id, idErr := platformInfoIdentity(info)
		if idErr != nil {
			return logOutput{}, errors.Join(idErr, file.Close())
		}
		s.fifoID = &id
	} else if !errors.Is(err, os.ErrNotExist) {
		return logOutput{}, errors.Join(err, file.Close())
	}
	return startBoundedLog(ctx, s), nil
}

func (s *unixLogSink) Write(data []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, os.ErrClosed
	}
	if s.fifoID == nil {
		f := s.diagnostics
		s.mu.Unlock()
		return f.Write(data)
	}
	info, err := s.paths.Bundle.Root.Lstat("log")
	if err != nil {
		s.mu.Unlock()
		return 0, err
	}
	id, err := platformInfoIdentity(info)
	if err != nil || id != *s.fifoID || info.Mode()&os.ModeNamedPipe == 0 {
		s.mu.Unlock()
		return 0, errors.Join(errPathChanged, err)
	}
	fd, err := unix.Openat(int(s.paths.Bundle.Handle.Fd()), "log", unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENXIO) {
		f := s.diagnostics
		s.mu.Unlock()
		return f.Write(data)
	}
	if err != nil {
		s.mu.Unlock()
		return 0, err
	}
	file := os.NewFile(uintptr(fd), "containerd log FIFO")
	openedInfo, err := file.Stat()
	if err == nil {
		id, err = platformInfoIdentity(openedInfo)
	}
	openedStat, ok := openedInfoSys(openedInfo)
	if err != nil || id != *s.fifoID || !ok || openedStat.Uid != uint32(os.Geteuid()) || openedStat.Nlink != 1 || openedInfo.Mode()&os.ModeNamedPipe == 0 || openedInfo.Mode().Perm()&0022 != 0 {
		s.mu.Unlock()
		return 0, errors.Join(errPathChanged, err, file.Close())
	}
	s.fifo = file
	s.mu.Unlock()
	n, err := s.writeFIFO(file, fd, data)
	s.mu.Lock()
	var closeErr error
	if s.fifo == file {
		s.fifo = nil
		closeErr = file.Close()
	}
	s.mu.Unlock()
	return n, errors.Join(err, closeErr)
}

func (s *unixLogSink) writeFIFO(file *os.File, fd int, data []byte) (int, error) {
	deadline := time.Now().Add(s.timeout)
	written := 0
	for written < len(data) {
		s.mu.Lock()
		if s.closed || s.fifo != file {
			s.mu.Unlock()
			return written, os.ErrClosed
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			s.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		n, err := unix.Write(fd, data[written:])
		if n > 0 {
			written += n
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			// Darwin excludes FIFOs from Go's deadline-aware poller.
			// Bound each native poll while the mutex protects against descriptor reuse.
			wait := min(remaining, 10*time.Millisecond)
			poll := [1]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
			_, err = unix.Poll(poll[:], int((wait+time.Millisecond-1)/time.Millisecond))
		}
		s.mu.Unlock()
		if err != nil && !errors.Is(err, unix.EINTR) {
			return written, err
		}
	}
	return written, nil
}

func (s *unixLogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.fifo != nil {
		err = s.fifo.Close()
		s.fifo = nil
	}
	return errors.Join(err, s.diagnostics.Close())
}

func openedInfoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok
}
