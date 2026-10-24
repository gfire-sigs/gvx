package gvxshim

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const maxTaskConnections = 32

var errInvalidTaskFrame = errors.New("invalid outbound ttRPC response frame")

type taskTransport struct {
	listener          net.Listener
	state             *controlState
	mu                sync.Mutex
	connections       map[*taskConnection]struct{}
	listenerClosed    bool
	connectionsClosed bool
	closeErr          error
}

func newTaskTransport(listener net.Listener, state *controlState) *taskTransport {
	return &taskTransport{listener: listener, state: state, connections: make(map[*taskConnection]struct{})}
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
		err = errors.Join(err, conn.Close())
	}
	return err
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
}

func (c *taskConnection) Close() error {
	c.closeOnce.Do(func() {
		// The raw close must interrupt writes without acquiring the parser lock.
		c.closeErr = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
	})
	return c.closeErr
}

func (c *taskConnection) Write(p []byte) (int, error) {
	// ttRPC owns one writer per connection. Parse only transport-accepted bytes.
	n, err := c.Conn.Write(p)
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
