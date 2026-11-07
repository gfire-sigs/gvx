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
// go-winio v0.6.2 listenerRoutine takes one close request in
// makeConnectedServerPipe. When the pending connect then fails with an error
// other than nil or ErrFileClosed (Accept returned ERROR_OPERATION_ABORTED in
// the failure on windows-latest), the routine does not record the close. It
// returns to its top-level select and waits for a second close request. The
// first Close then waits forever on doneCh. Each further Close call sends one
// more request, so Close is repeated until one returns. The wait has an upper
// bound because the operating system can also leave a connect pending.
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
			return errPipeListenerCloseTimeout
		}
	}
}
