package gvxshim

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
)

var errLogRecordTooLarge = errors.New("log record exceeds 4096 bytes")
var errLogQueueFull = errors.New("log queue contains 64 records")

type logSink interface {
	Write([]byte) (int, error)
	Close() error
}

type boundedLog struct {
	mu     sync.Mutex
	queue  chan []byte
	done   chan struct{}
	closed bool
	cancel context.CancelFunc
	sink   logSink
	err    error
}

func startBoundedLog(ctx context.Context, sink logSink) logOutput {
	workerCtx, cancel := context.WithCancel(ctx)
	l := &boundedLog{queue: make(chan []byte, 64), done: make(chan struct{}), cancel: cancel, sink: sink}
	stop := context.AfterFunc(workerCtx, func() { l.mu.Lock(); l.closed = true; l.mu.Unlock(); sink.Close() })
	go func() {
		defer close(l.done)
		defer stop()
		defer sink.Close()
		for {
			if workerCtx.Err() != nil {
				return
			}
			select {
			case <-workerCtx.Done():
				return
			case record := <-l.queue:
				_, err := sink.Write(record)
				if err != nil && workerCtx.Err() == nil {
					l.mu.Lock()
					l.err = errors.Join(l.err, err)
					l.mu.Unlock()
				}
			}
		}
	}()
	return logOutput{Writer: l, Close: l.close}
}

func (l *boundedLog) Write(data []byte) (int, error) {
	if len(data) > 4096 {
		return 0, errLogRecordTooLarge
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, os.ErrClosed
	}
	if l.err != nil {
		return 0, l.err
	}
	// Copy only accepted records; callers retain ownership of their buffers.
	if len(l.queue) == cap(l.queue) {
		return 0, errLogQueueFull
	}
	record := make([]byte, len(data))
	copy(record, data)
	select {
	case l.queue <- record:
		return len(data), nil
	default:
		return 0, errLogQueueFull
	}
}

func (l *boundedLog) close(ctx context.Context) error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.cancel()
	closeErr := l.sink.Close()
	// Closing the transport cancels pending writes before joining the worker.
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(closeErr, l.err, ctx.Err())
}

func openDiagnostics(paths *instancePaths, expected ownedEntry) (*os.File, error) {
	if expected.Name != "diagnostics.log" || expected.Kind != regularEntry {
		return nil, errUnsafeEntry
	}
	actual, err := inspectEntry(paths.State, expected.Name, regularEntry)
	if err != nil {
		return nil, err
	}
	if actual != expected {
		return nil, errPathChanged
	}
	file, err := openPrivateFile(paths.State, expected.Name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	id, err := validateFile(file, regularEntry, true)
	if err != nil || id != expected.Identity {
		return nil, errors.Join(errPathChanged, err, file.Close())
	}
	return file, nil
}

var _ io.Writer = (*boundedLog)(nil)
