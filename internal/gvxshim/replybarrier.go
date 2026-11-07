package gvxshim

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const maxTaskConnections = 32

// peerCloseGrace bounds how long a connection that wrote a response waits for
// the peer to close before the shim closes it. A ttRPC client cancels its
// context when it reads end-of-file, and a call that has not yet taken its
// response from the stream can return ErrClosed instead of the response. The
// peer closes first in normal use, so the wait is short. A peer that keeps the
// connection open delays the close by this time.
const peerCloseGrace = time.Second

var errInvalidTaskFrame = errors.New("invalid outbound ttRPC response frame")

type taskTransport struct {
	listener          net.Listener
	state             *controlState
	mu                sync.Mutex
	connections       map[*taskConnection]struct{}
	listenerClosed    bool
	connectionsClosed bool
	closeErr          error
	changed           chan struct{}
}

func newTaskTransport(listener net.Listener, state *controlState) *taskTransport {
	return &taskTransport{listener: listener, state: state, connections: make(map[*taskConnection]struct{}), changed: make(chan struct{})}
}

func (t *taskTransport) Accept() (net.Conn, error) {
	for {
		raw, err := t.listener.Accept()
		if err != nil {
			return nil, err
		}
		t.mu.Lock()
		closed := t.listenerClosed || t.connectionsClosed
		if closed || len(t.connections) >= maxTaskConnections {
			t.mu.Unlock()
			if err := raw.Close(); err != nil {
				return nil, err
			}
			if closed {
				return nil, net.ErrClosed
			}
			continue
		}
		conn := &taskConnection{Conn: raw, owner: t}
		t.connections[conn] = struct{}{}
		t.mu.Unlock()
		return conn, nil
	}
}

func (t *taskTransport) Addr() net.Addr { return t.listener.Addr() }

func (t *taskTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.listenerClosed {
		t.listenerClosed = true
		t.closeErr = t.listener.Close()
	}
	return t.closeErr
}

func (t *taskTransport) CloseConnections() error {
	var connections [maxTaskConnections]*taskConnection
	t.mu.Lock()
	t.connectionsClosed = true
	n := 0
	for conn := range t.connections {
		connections[n] = conn
		n++
	}
	t.mu.Unlock()
	var err error
	for _, conn := range connections[:n] {
		err = errors.Join(err, conn.abort())
	}
	return err
}

// AwaitConnections returns when every accepted connection has closed or ctx
// ends. Call it after the listener closes so that no connection is added during
// the wait. The caller closes the remaining connections with CloseConnections.
func (t *taskTransport) AwaitConnections(ctx context.Context) {
	for {
		t.mu.Lock()
		open, changed := len(t.connections), t.changed
		t.mu.Unlock()
		if open == 0 {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return
		}
	}
}

type taskConnection struct {
	net.Conn
	owner       *taskTransport
	closeOnce   sync.Once
	closeErr    error
	mu          sync.Mutex
	header      [10]byte
	headerBytes int
	bodyBytes   uint32
	frameErr    error
	wrote       atomic.Bool
}

// Close is the ttRPC close path. A connection that wrote bytes stays open until
// the peer closes it or peerCloseGrace passes, so that the peer reads the last
// response before it reads end-of-file. The shim process closes every
// connection through abort after the wait.
func (c *taskConnection) Close() error {
	if c.wrote.Load() {
		c.awaitPeerClose()
	}
	return c.abort()
}

func (c *taskConnection) awaitPeerClose() {
	if c.Conn.SetReadDeadline(time.Now().Add(peerCloseGrace)) != nil {
		return
	}
	var discard [512]byte
	for {
		if _, err := c.Conn.Read(discard[:]); err != nil {
			return
		}
	}
}

// abort closes the connection at once and interrupts a blocked Read or Write.
func (c *taskConnection) abort() error {
	c.closeOnce.Do(func() {
		// The raw close must interrupt writes without acquiring the parser lock.
		c.closeErr = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		close(c.owner.changed)
		c.owner.changed = make(chan struct{})
		c.owner.mu.Unlock()
	})
	return c.closeErr
}

func (c *taskConnection) Write(p []byte) (int, error) {
	// ttRPC owns one writer per connection. Parse only transport-accepted bytes.
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.wrote.Store(true)
	}
	if n < 0 || n > len(p) {
		c.owner.state.RequestStop()
		return n, errors.Join(err, errInvalidTaskFrame)
	}
	c.mu.Lock()
	frameErr := c.observe(p[:n])
	c.mu.Unlock()
	if frameErr != nil {
		c.owner.state.RequestStop()
		return n, errors.Join(err, frameErr)
	}
	if n < len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (c *taskConnection) observe(p []byte) error {
	if c.frameErr != nil {
		return c.frameErr
	}
	for len(p) > 0 {
		if c.bodyBytes > 0 {
			n := min(uint32(len(p)), c.bodyBytes)
			p = p[n:]
			c.bodyBytes -= n
			continue
		}
		n := copy(c.header[c.headerBytes:], p)
		c.headerBytes += n
		p = p[n:]
		if c.headerBytes < len(c.header) {
			continue
		}
		length := binary.BigEndian.Uint32(c.header[:4])
		if length > 4<<20 || c.header[8] != 0x02 || c.header[9] != 0 {
			c.frameErr = errInvalidTaskFrame
			return c.frameErr
		}
		c.headerBytes = 0
		c.bodyBytes = length
		if length != 0 {
			continue
		}
		// Error responses may echo invalid stream IDs, but successful calls cannot.
		if binary.BigEndian.Uint32(c.header[4:8])&1 == 0 {
			c.frameErr = errInvalidTaskFrame
			return c.frameErr
		}
		if err := c.owner.state.ReplyWritten(); err != nil {
			c.frameErr = err
			return err
		}
	}
	return nil
}
