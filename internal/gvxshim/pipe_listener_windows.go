package gvxshim

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pipeListenerCloseRetry   = 10 * time.Millisecond
	pipeListenerCloseTimeout = 5 * time.Second
)

var errPipeListenerCloseTimeout = errors.New("named pipe listener did not close in time")

// pipeListener makes Close of a go-winio pipe listener finish.
//
// In go-winio v0.6.2, the close branch of makeConnectedServerPipe takes one
// close request. It maps only nil and ErrFileClosed to ErrPipeListenerClosed.
// If the pending connect ends with another error, the listener routine does not
// record the close. A raw ERROR_OPERATION_ABORTED returns to Accept, and the
// routine goes back to its top-level select. ERROR_NO_DATA makes the routine
// connect again. Both cases wait for a second close request, so the first Close
// waits forever on doneCh.
//
// Each Close call sends one more request. Repeat Close until one call returns.
// The operating system can also keep a connect pending, so the wait has an
// upper bound. The inner Close error is dropped because go-winio always
// returns nil.
type pipeListener struct {
	net.Listener
	closing atomic.Bool
	retry   time.Duration
	timeout time.Duration
}

func newPipeListener(inner net.Listener) *pipeListener {
	return &pipeListener{Listener: inner, retry: pipeListenerCloseRetry, timeout: pipeListenerCloseTimeout}
}

// Accept reports every failure that follows Close as net.ErrClosed. go-winio
// returns the raw connect error when Close cancels a pending connect.
func (l *pipeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil && l.closing.Load() {
		return nil, net.ErrClosed
	}
	return conn, err
}

func (l *pipeListener) Close() error {
	l.closing.Store(true)
	returned := make(chan struct{})
	var once sync.Once
	attempt := func() {
		go func() {
			l.Listener.Close()
			once.Do(func() { close(returned) })
		}()
	}
	ticker := time.NewTicker(l.retry)
	defer ticker.Stop()
	timer := time.NewTimer(l.timeout)
	defer timer.Stop()
	attempt()
	for {
		select {
		case <-returned:
			return nil
		case <-ticker.C:
			attempt()
		case <-timer.C:
			select {
			case <-returned:
				return nil
			default:
				return errPipeListenerCloseTimeout
			}
		}
	}
}
