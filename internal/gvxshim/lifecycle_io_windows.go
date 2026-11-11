//go:build windows

package gvxshim

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

var cancelSynchronousIO = windows.NewLazySystemDLL("kernel32.dll").NewProc("CancelSynchronousIo")

type windowsBoundedStream struct {
	ctx              context.Context
	handle           windows.Handle
	event            windows.Handle
	activeOverlapped atomic.Pointer[windows.Overlapped]
	seekable         bool
	offset           int64
}

func boundedFileIO(ctx context.Context, file *os.File, operation func(io.ReadWriter) error) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cancelSynchronousIO.Find(); err != nil {
		return err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var handle windows.Handle
	var duplicateError error
	process := windows.CurrentProcess()
	if err := raw.Control(func(source uintptr) {
		duplicateError = windows.DuplicateHandle(process, windows.Handle(source), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS)
	}); err != nil {
		return err
	}
	if duplicateError != nil {
		return duplicateError
	}
	defer func() { result = errors.Join(result, windows.CloseHandle(handle)) }()
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return err
	}
	seekable := kind == windows.FILE_TYPE_DISK
	var event windows.Handle
	if seekable {
		event, err = windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, windows.CloseHandle(event)) }()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var thread windows.Handle
	if err := windows.DuplicateHandle(process, windows.CurrentThread(), process, &thread, windows.THREAD_TERMINATE, false, 0); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, windows.CloseHandle(thread)) }()
	stream := &windowsBoundedStream{ctx: ctx, handle: handle, event: event, seekable: seekable}
	completed := make(chan struct{})
	cancelled := make(chan struct{})
	var cancellationError error
	go func() {
		defer close(cancelled)
		select {
		case <-completed:
			return
		case <-ctx.Done():
		}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			// Cancellation can precede syscall entry; retry until the owned operation returns.
			value, _, callError := cancelSynchronousIO.Call(uintptr(thread))
			if value == 0 && !errors.Is(callError, windows.ERROR_NOT_FOUND) && cancellationError == nil {
				cancellationError = callError
			}
			if !stream.seekable {
				if err := windows.CancelIoEx(handle, nil); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) && cancellationError == nil {
					cancellationError = err
				}
			} else if ov := stream.activeOverlapped.Load(); ov != nil {
				if err := windows.CancelIoEx(handle, ov); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) && cancellationError == nil {
					cancellationError = err
				}
			}
			select {
			case <-completed:
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() {
		close(completed)
		<-cancelled
		if result != nil {
			result = errors.Join(ctx.Err(), result, cancellationError)
		}
	}()
	if stream.seekable {
		stream.offset, result = windows.Seek(handle, 0, io.SeekCurrent)
	}
	if result == nil {
		result = operation(stream)
	}
	return result
}

func (s *windowsBoundedStream) Read(data []byte) (int, error)  { return s.transfer(data, true) }
func (s *windowsBoundedStream) Write(data []byte) (int, error) { return s.transfer(data, false) }

func (s *windowsBoundedStream) transfer(data []byte, reading bool) (int, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	var count uint32
	var err error
	if !s.seekable {
		if reading {
			err = windows.ReadFile(s.handle, data, &count, nil)
		} else {
			err = windows.WriteFile(s.handle, data, &count, nil)
		}
	} else {
		if err := windows.ResetEvent(s.event); err != nil {
			return 0, err
		}
		// The low event bit keeps private OVERLAPPED completions out of Go's IOCP.
		ov := &windows.Overlapped{
			HEvent:     s.event | 1,
			Offset:     uint32(s.offset),
			OffsetHigh: uint32(uint64(s.offset) >> 32),
		}
		s.activeOverlapped.Store(ov)
		if reading {
			err = windows.ReadFile(s.handle, data, &count, ov)
		} else {
			err = windows.WriteFile(s.handle, data, &count, ov)
		}
		if errors.Is(err, windows.ERROR_IO_PENDING) {
			err = windows.GetOverlappedResult(s.handle, ov, &count, true)
		}
		s.activeOverlapped.Store(nil)
		runtime.KeepAlive(ov)
		if count != 0 {
			s.offset += int64(count)
			_, seekError := windows.Seek(s.handle, s.offset, io.SeekStart)
			err = errors.Join(err, seekError)
		}
	}
	if reading && (errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF) || (err == nil && count == 0)) {
		err = io.EOF
	}
	runtime.KeepAlive(data)
	runtime.KeepAlive(s)
	return int(count), err
}

var _ io.ReadWriter = (*windowsBoundedStream)(nil)
