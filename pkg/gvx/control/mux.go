// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

const (
	maxChannelsPerStream = 4
	maxBufferedEvents    = 4096
	maxStreamRXBuffer    = InitialStreamWindow * 2
	maxConcurrentStreams = 128
)

// prefixReader drains an optional buffered preface before reading directly from
// the underlying net.Conn so SCM_RIGHTS ReadMsgUnix calls stay aligned.
type prefixReader struct {
	prefix []byte
	conn   net.Conn
}

func (p *prefixReader) Read(dst []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(dst, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.conn.Read(dst)
}

type incomingRequest struct {
	stream *Stream
	env    RequestEnvelope
	fds    []int
}

// Conn manages a multiplexed gvx-ctrl/2 binary connection.
type Conn struct {
	raw           net.Conn
	reader        *prefixReader
	maxFrameBytes int
	isServer      bool
	allowFDs      bool

	writeMu sync.Mutex
	ctrlOut chan Frame

	mu         sync.Mutex
	streams    map[uint32]*Stream
	pings      map[uint64]chan struct{}
	closed     bool
	closeErr   error
	goingAway  bool
	onRequest  func(incomingRequest)
	nextID     atomic.Uint32
	pingSeq    atomic.Uint64
	done       chan struct{}
	closeOnce  sync.Once
	inFlightWG sync.WaitGroup
}

func newConn(raw net.Conn, prefix []byte, maxFrameBytes int, isServer, allowFDs bool, onRequest func(incomingRequest)) *Conn {
	if maxFrameBytes <= 0 || maxFrameBytes > AbsoluteMaxFrameBytes {
		maxFrameBytes = DefaultMaxFrameBytes
	}
	c := &Conn{
		raw:           raw,
		reader:        &prefixReader{prefix: prefix, conn: raw},
		maxFrameBytes: maxFrameBytes,
		isServer:      isServer,
		allowFDs:      allowFDs,
		ctrlOut:       make(chan Frame, 32),
		streams:       make(map[uint32]*Stream),
		pings:         make(map[uint64]chan struct{}),
		onRequest:     onRequest,
		done:          make(chan struct{}),
	}
	if isServer {
		c.nextID.Store(0)
	} else {
		c.nextID.Store(1)
	}
	return c
}

func (c *Conn) startReadLoop() {
	go c.ctrlWriteLoop()
	go c.readLoop()
}

func (c *Conn) ctrlWriteLoop() {
	for {
		select {
		case f := <-c.ctrlOut:
			_ = c.writeFrame(f)
		case <-c.done:
			return
		}
	}
}

func (c *Conn) enqueueCtrlFrame(f Frame) {
	select {
	case c.ctrlOut <- f:
	case <-c.done:
	default:
	}
}

// Done returns a channel closed when the connection terminates.
func (c *Conn) Done() <-chan struct{} {
	return c.done
}

// Close closes the underlying connection and cancels all active streams.
func (c *Conn) Close() error {
	return c.closeWithError(ErrConnClosed)
}

func (c *Conn) closeWithError(err error) error {
	var closeNetErr error
	c.closeOnce.Do(func() {
		if err == nil {
			err = ErrConnClosed
		}
		c.mu.Lock()
		c.closed = true
		c.closeErr = err
		streams := make([]*Stream, 0, len(c.streams))
		for _, s := range c.streams {
			streams = append(streams, s)
		}
		c.streams = make(map[uint32]*Stream)
		for k, ch := range c.pings {
			close(ch)
			delete(c.pings, k)
		}
		c.mu.Unlock()

		for _, s := range streams {
			s.abort(err)
		}
		closeNetErr = c.raw.Close()
		close(c.done)
	})
	return closeNetErr
}

// SendGoAway informs the peer that no new streams will be accepted.
func (c *Conn) SendGoAway(reason string) error {
	c.mu.Lock()
	c.goingAway = true
	c.mu.Unlock()
	var payload []byte
	if reason != "" {
		payload, _ = json.Marshal(NewError(CodeSandboxExiting, reason))
	}
	return c.writeFrame(Frame{
		Type:    FrameGoAway,
		Payload: payload,
	})
}

// Ping sends a wire-level ping frame and waits for the matching pong.
func (c *Conn) Ping(ctx context.Context) error {
	seq := c.pingSeq.Add(1)
	ch := make(chan struct{})
	c.mu.Lock()
	if c.closed {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.pings[seq] = ch
	c.mu.Unlock()

	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], seq)
	if err := c.writeFrame(Frame{
		Type:    FramePing,
		Payload: payload[:],
	}); err != nil {
		c.mu.Lock()
		delete(c.pings, seq)
		c.mu.Unlock()
		return err
	}

	select {
	case <-ch:
		c.mu.Lock()
		closed := c.closed
		err := c.closeErr
		c.mu.Unlock()
		if closed {
			return err
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pings, seq)
		c.mu.Unlock()
		return ctx.Err()
	case <-c.done:
		return c.err()
	}
}

func (c *Conn) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return ErrConnClosed
}

func (c *Conn) activeStreams() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}

func (c *Conn) writeFrame(f Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrameLocked(f)
}

// writeFrameLocked requires writeMu through both the frame and any descriptors.
func (c *Conn) writeFrameLocked(f Frame) error {
	if len(f.FDs) > 0 {
		f.Flags |= FlagHasFDs
	}
	if err := WriteFrame(c.raw, f, c.maxFrameBytes); err != nil {
		return err
	}
	if len(f.FDs) > 0 {
		if err := SendFDs(c.raw, f.FDs); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) allocStream(ctx context.Context) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, c.closeErr
	}
	if c.goingAway {
		return nil, NewError(CodeSandboxExiting, "control connection is shutting down")
	}
	if len(c.streams) >= maxConcurrentStreams {
		return nil, NewError(CodeLimitExceeded, "too many concurrent control streams")
	}
	id := c.nextID.Add(2) - 2
	if id == 0 {
		id = c.nextID.Add(2) - 2
	}
	s := newStream(ctx, c, id)
	c.streams[id] = s
	return s, nil
}

func (c *Conn) removeStream(id uint32) {
	c.mu.Lock()
	delete(c.streams, id)
	shouldClose := c.goingAway && len(c.streams) == 0
	c.mu.Unlock()
	if shouldClose {
		go func() { _ = c.Close() }()
	}
}

func (c *Conn) lookupStream(id uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *Conn) readLoop() {
	for {
		f, err := ReadFrame(c.reader, c.maxFrameBytes)
		if err != nil {
			_ = c.closeWithError(err)
			return
		}
		if f.Flags&FlagHasFDs != 0 {
			if !c.allowFDs || f.Type != FrameRequest || len(c.reader.prefix) > 0 {
				_ = c.closeWithError(errors.New("control: unexpected SCM_RIGHTS file descriptors"))
				return
			}
			fds, fdErr := RecvFDs(c.raw, 4)
			if fdErr != nil {
				_ = c.closeWithError(fdErr)
				return
			}
			f.FDs = fds
		}
		if err := c.dispatchFrame(f); err != nil {
			closeFDs(f.FDs)
			_ = c.closeWithError(err)
			return
		}
	}
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		closeFD(fd)
	}
}

func (c *Conn) dispatchFrame(f Frame) error {
	switch f.Type {
	case FramePing:
		closeFDs(f.FDs)
		c.enqueueCtrlFrame(Frame{Type: FramePong, Payload: f.Payload})
		return nil

	case FramePong:
		closeFDs(f.FDs)
		if len(f.Payload) == 8 {
			seq := binary.BigEndian.Uint64(f.Payload)
			c.mu.Lock()
			if ch, ok := c.pings[seq]; ok {
				delete(c.pings, seq)
				close(ch)
			}
			c.mu.Unlock()
		}
		return nil

	case FrameGoAway:
		closeFDs(f.FDs)
		c.mu.Lock()
		c.goingAway = true
		c.mu.Unlock()
		return nil

	case FrameRequest:
		if !c.isServer || f.StreamID == 0 {
			closeFDs(f.FDs)
			return errors.New("control: unexpected request frame")
		}
		var env RequestEnvelope
		if err := json.Unmarshal(f.Payload, &env); err != nil {
			closeFDs(f.FDs)
			return fmt.Errorf("control: decode request envelope: %w", err)
		}
		c.mu.Lock()
		if c.goingAway || c.closed {
			c.mu.Unlock()
			closeFDs(f.FDs)
			if payload, mErr := json.Marshal(ResponseEnvelope{
				OK:    false,
				Error: NewError(CodeSandboxExiting, "control server is shutting down"),
			}); mErr == nil {
				c.enqueueCtrlFrame(Frame{
					Type:     FrameResponse,
					Flags:    FlagEndStream,
					StreamID: f.StreamID,
					Payload:  payload,
				})
			}
			return nil
		}
		if _, exists := c.streams[f.StreamID]; exists {
			c.mu.Unlock()
			closeFDs(f.FDs)
			return fmt.Errorf("control: duplicate stream id %d", f.StreamID)
		}
		if len(c.streams) >= maxConcurrentStreams {
			c.mu.Unlock()
			closeFDs(f.FDs)
			if payload, mErr := json.Marshal(ResponseEnvelope{
				OK:    false,
				Error: NewError(CodeLimitExceeded, "too many concurrent control streams"),
			}); mErr == nil {
				c.enqueueCtrlFrame(Frame{
					Type:     FrameResponse,
					Flags:    FlagEndStream,
					StreamID: f.StreamID,
					Payload:  payload,
				})
			}
			return nil
		}
		s := newStream(context.Background(), c, f.StreamID)
		if f.Flags&FlagEndStream != 0 {
			s.markChannelEOF(ChannelGeneric)
		}
		c.streams[f.StreamID] = s
		onReq := c.onRequest
		c.mu.Unlock()

		if onReq != nil {
			onReq(incomingRequest{stream: s, env: env, fds: f.FDs})
		} else {
			closeFDs(f.FDs)
		}
		return nil

	case FrameResponse:
		closeFDs(f.FDs)
		s := c.lookupStream(f.StreamID)
		if s == nil {
			return nil
		}
		var env ResponseEnvelope
		if err := json.Unmarshal(f.Payload, &env); err != nil {
			s.abort(fmt.Errorf("control: decode response envelope: %w", err))
			return nil
		}
		s.deliverResponse(env, f.Flags&FlagEndStream != 0)
		return nil

	case FrameData:
		closeFDs(f.FDs)
		s := c.lookupStream(f.StreamID)
		if s == nil {
			return nil
		}
		if int(f.Channel) >= maxChannelsPerStream {
			return fmt.Errorf("control: invalid data channel %d", f.Channel)
		}
		if err := s.deliverData(f.Channel, f.Payload, f.Flags&FlagEndStream != 0); err != nil {
			return err
		}
		return nil

	case FrameEvent:
		closeFDs(f.FDs)
		s := c.lookupStream(f.StreamID)
		if s == nil {
			return nil
		}
		if len(f.Payload) == 0 && f.Flags&FlagEndStream != 0 {
			s.markEventsEOF()
			return nil
		}
		var env EventEnvelope
		if err := json.Unmarshal(f.Payload, &env); err != nil {
			s.abort(fmt.Errorf("control: decode event envelope: %w", err))
			return nil
		}
		if err := s.deliverEvent(env, f.Flags&FlagEndStream != 0); err != nil {
			return err
		}
		return nil

	case FrameWindowUpdate:
		closeFDs(f.FDs)
		if len(f.Payload) != 4 {
			return errors.New("control: invalid WINDOW_UPDATE payload length")
		}
		delta := int64(binary.BigEndian.Uint32(f.Payload))
		if delta <= 0 {
			return errors.New("control: non-positive WINDOW_UPDATE increment")
		}
		if s := c.lookupStream(f.StreamID); s != nil {
			s.addSendWindow(delta)
		}
		return nil

	case FrameCancel:
		closeFDs(f.FDs)
		var cancelErr error = context.Canceled
		if len(f.Payload) > 0 {
			var pe ProtoError
			if err := json.Unmarshal(f.Payload, &pe); err == nil && pe.Code != "" {
				cancelErr = &pe
			}
		}
		if s := c.lookupStream(f.StreamID); s != nil {
			s.abort(cancelErr)
		}
		return nil

	default:
		closeFDs(f.FDs)
		return fmt.Errorf("control: unknown frame type 0x%02x", byte(f.Type))
	}
}

func (c *Conn) writeResponseEnvelope(streamID uint32, env ResponseEnvelope, flags FrameFlags) error {
	payload, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return c.writeFrame(Frame{
		Type:     FrameResponse,
		Flags:    flags,
		StreamID: streamID,
		Payload:  payload,
	})
}

type dataQueue struct {
	chunks   [][]byte
	buffered int
	eof      bool
	notify   chan struct{}
}

func newDataQueue() dataQueue {
	return dataQueue{notify: make(chan struct{})}
}

// Stream represents one logical RPC and its multiplexed data/event channels.
type Stream struct {
	id     uint32
	conn   *Conn
	ctx    context.Context
	cancel context.CancelFunc

	respCh   chan ResponseEnvelope
	respOnce sync.Once
	respSent atomic.Bool

	sendMu     sync.Mutex
	sendWindow int64
	sendNotify chan struct{}
	closedSend [maxChannelsPerStream]bool

	rxMu        sync.Mutex
	queues      [maxChannelsPerStream]dataQueue
	rxTotal     int
	rxConsumed  int
	events      []EventEnvelope
	eventsEOF   bool
	eventNotify chan struct{}
	err         error
	done        chan struct{}
	closeOnce   sync.Once
}

func newStream(parent context.Context, conn *Conn, id uint32) *Stream {
	ctx, cancel := context.WithCancel(parent)
	s := &Stream{
		id:          id,
		conn:        conn,
		ctx:         ctx,
		cancel:      cancel,
		respCh:      make(chan ResponseEnvelope, 1),
		sendWindow:  InitialStreamWindow,
		sendNotify:  make(chan struct{}),
		eventNotify: make(chan struct{}),
		done:        make(chan struct{}),
	}
	for i := range s.queues {
		s.queues[i] = newDataQueue()
	}
	return s
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 {
	return s.id
}

// Context returns the stream context, canceled when the stream or connection ends.
func (s *Stream) Context() context.Context {
	return s.ctx
}

// PeerAddr returns the transport connection's remote address, not an address
// supplied by the RPC peer. Callers must not modify the address.
func (s *Stream) PeerAddr() net.Addr {
	return s.conn.raw.RemoteAddr()
}

// Close terminates the local stream state and detaches it from its connection.
func (s *Stream) Close() {
	s.closeOnce.Do(func() {
		s.rxMu.Lock()
		if s.err == nil {
			s.err = ErrStreamClosed
		}
		for i := range s.queues {
			close(s.queues[i].notify)
			s.queues[i].notify = make(chan struct{})
		}
		close(s.eventNotify)
		s.eventNotify = make(chan struct{})
		s.rxMu.Unlock()

		s.sendMu.Lock()
		close(s.sendNotify)
		s.sendNotify = make(chan struct{})
		s.sendMu.Unlock()

		s.cancel()
		close(s.done)
		s.conn.removeStream(s.id)
	})
}

// Cancel sends FrameCancel to the peer with an optional error and closes the stream.
func (s *Stream) Cancel(err error) {
	var payload []byte
	if err != nil {
		var pe *ProtoError
		if errors.As(err, &pe) {
			payload, _ = json.Marshal(pe)
		} else {
			payload, _ = json.Marshal(NewError(CodeInternal, err.Error()))
		}
	}
	_ = s.conn.writeFrame(Frame{
		Type:     FrameCancel,
		StreamID: s.id,
		Payload:  payload,
	})
	s.abort(err)
}

func (s *Stream) abort(err error) {
	if err == nil {
		err = ErrStreamClosed
	}
	s.rxMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.rxMu.Unlock()
	s.Close()
}

func (s *Stream) streamErr() error {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if s.err != nil {
		return s.err
	}
	return ErrStreamClosed
}

func (s *Stream) deliverResponse(env ResponseEnvelope, endStream bool) {
	s.respOnce.Do(func() {
		s.respCh <- env
	})
	if endStream {
		s.rxMu.Lock()
		for i := range s.queues {
			s.queues[i].eof = true
			close(s.queues[i].notify)
			s.queues[i].notify = make(chan struct{})
		}
		s.eventsEOF = true
		close(s.eventNotify)
		s.eventNotify = make(chan struct{})
		s.rxMu.Unlock()
	}
}

func (s *Stream) markChannelEOF(ch Channel) {
	if int(ch) >= maxChannelsPerStream {
		return
	}
	s.rxMu.Lock()
	q := &s.queues[ch]
	q.eof = true
	close(q.notify)
	q.notify = make(chan struct{})
	s.rxMu.Unlock()
}

func (s *Stream) deliverData(ch Channel, payload []byte, endStream bool) error {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if s.err != nil {
		return nil
	}
	q := &s.queues[ch]
	if len(payload) > 0 {
		if s.rxTotal+len(payload) > maxStreamRXBuffer {
			return errors.New("control: peer exceeded stream flow-control window")
		}
		q.chunks = append(q.chunks, payload)
		q.buffered += len(payload)
		s.rxTotal += len(payload)
	}
	if endStream {
		q.eof = true
	}
	close(q.notify)
	q.notify = make(chan struct{})
	return nil
}

func (s *Stream) deliverEvent(env EventEnvelope, endStream bool) error {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if s.err != nil {
		return nil
	}
	if len(s.events) >= maxBufferedEvents {
		return errors.New("control: stream event queue overflow")
	}
	s.events = append(s.events, env)
	if endStream {
		s.eventsEOF = true
	}
	close(s.eventNotify)
	s.eventNotify = make(chan struct{})
	return nil
}

func (s *Stream) markEventsEOF() {
	s.rxMu.Lock()
	s.eventsEOF = true
	close(s.eventNotify)
	s.eventNotify = make(chan struct{})
	s.rxMu.Unlock()
}

func (s *Stream) addSendWindow(delta int64) {
	s.sendMu.Lock()
	s.sendWindow += delta
	close(s.sendNotify)
	s.sendNotify = make(chan struct{})
	s.sendMu.Unlock()
}

// SendResponse sends a successful non-terminal response header for streaming RPCs.
func (s *Stream) SendResponse(result any) error {
	return s.sendResponse(result, 0)
}

// Reply sends a successful terminal response for unary RPCs.
func (s *Stream) Reply(result any) error {
	return s.sendResponse(result, FlagEndStream)
}

func (s *Stream) sendResponse(result any, flags FrameFlags) error {
	var raw json.RawMessage
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("control: marshal response: %w", err)
		}
		raw = b
	}
	payload, err := json.Marshal(ResponseEnvelope{OK: true, Result: raw})
	if err != nil {
		return fmt.Errorf("control: marshal response envelope: %w", err)
	}
	if len(payload) > s.conn.maxFrameBytes {
		return NewError(CodeLimitExceeded, "response exceeds the negotiated frame size")
	}
	if !s.respSent.CompareAndSwap(false, true) {
		return nil
	}
	return s.conn.writeFrame(Frame{
		Type:     FrameResponse,
		Flags:    flags,
		StreamID: s.id,
		Payload:  payload,
	})
}

// SendError sends a terminal error response if no response has been sent yet.
func (s *Stream) SendError(err error) error {
	if !s.respSent.CompareAndSwap(false, true) {
		return nil
	}
	var pe *ProtoError
	if !errors.As(err, &pe) {
		pe = NewError(CodeInternal, err.Error())
	}
	return s.conn.writeResponseEnvelope(s.id, ResponseEnvelope{
		OK:    false,
		Error: pe,
	}, FlagEndStream)
}

// WaitResponse waits for the server's FrameResponse and unmarshals Result into out
// when out is non-nil.
func (s *Stream) WaitResponse(ctx context.Context, out any) error {
	select {
	case env := <-s.respCh:
		if !env.OK {
			if env.Error != nil {
				return env.Error
			}
			return NewError(CodeInternal, "request failed without error details")
		}
		if out != nil && len(env.Result) > 0 {
			if err := json.Unmarshal(env.Result, out); err != nil {
				return fmt.Errorf("control: decode response result: %w", err)
			}
		}
		return nil
	case <-ctx.Done():
		s.Cancel(ctx.Err())
		return ctx.Err()
	case <-s.done:
		// Check whether a response arrived concurrently before close.
		select {
		case env := <-s.respCh:
			if !env.OK {
				if env.Error != nil {
					return env.Error
				}
				return NewError(CodeInternal, "request failed")
			}
			if out != nil && len(env.Result) > 0 {
				if err := json.Unmarshal(env.Result, out); err != nil {
					return fmt.Errorf("control: decode response result: %w", err)
				}
			}
			return nil
		default:
			return s.streamErr()
		}
	}
}

// WriteData writes p to channel ch, respecting flow-control credits and chunking
// payloads to stay under the negotiated MaxFrameBytes.
// Cancellation prevents subsequent frames without truncating a committed frame.
func (s *Stream) WriteData(ctx context.Context, ch Channel, p []byte, compress bool) error {
	_, err := s.writeData(ctx, ch, p, compress)
	return err
}

func (s *Stream) writeData(ctx context.Context, ch Channel, p []byte, compress bool) (int, error) {
	if int(ch) >= maxChannelsPerStream {
		return 0, fmt.Errorf("control: invalid data channel %d", ch)
	}
	maxChunk := s.conn.maxFrameBytes
	if maxChunk <= 0 {
		maxChunk = DefaultMaxFrameBytes
	}
	var written int
	for len(p) > 0 {
		n, err := s.consumeSendWindow(ctx, len(p), maxChunk)
		if err != nil {
			return written, err
		}
		chunk := p[:n]
		p = p[n:]
		var flags FrameFlags
		if compress {
			flags |= FlagCompressedZstd
		}
		if err := s.writeDataFrame(ctx, Frame{
			Type:     FrameData,
			Flags:    flags,
			Channel:  ch,
			StreamID: s.id,
			Payload:  chunk,
		}); err != nil {
			return written, err
		}
		written += n
	}
	return written, nil
}

func (s *Stream) writeDataFrame(ctx context.Context, f Frame) error {
	s.conn.writeMu.Lock()
	defer s.conn.writeMu.Unlock()
	// This check commits the frame. Cancellation after it must not split the frame.
	if err := ctx.Err(); err != nil {
		s.addSendWindow(int64(len(f.Payload)))
		return err
	}
	return s.conn.writeFrameLocked(f)
}

func (s *Stream) consumeSendWindow(ctx context.Context, want, maxChunk int) (int, error) {
	for {
		s.sendMu.Lock()
		if s.sendWindow > 0 {
			n := want
			if n > maxChunk {
				n = maxChunk
			}
			if int64(n) > s.sendWindow {
				n = int(s.sendWindow)
			}
			s.sendWindow -= int64(n)
			s.sendMu.Unlock()
			return n, nil
		}
		waitCh := s.sendNotify
		s.sendMu.Unlock()

		select {
		case <-waitCh:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			return 0, s.streamErr()
		}
	}
}

// CloseChannel sends an empty FrameData with FlagEndStream on ch.
func (s *Stream) CloseChannel(ch Channel) error {
	if int(ch) >= maxChannelsPerStream {
		return fmt.Errorf("control: invalid data channel %d", ch)
	}
	s.sendMu.Lock()
	if s.closedSend[ch] {
		s.sendMu.Unlock()
		return nil
	}
	s.closedSend[ch] = true
	s.sendMu.Unlock()
	return s.conn.writeFrame(Frame{
		Type:     FrameData,
		Flags:    FlagEndStream,
		Channel:  ch,
		StreamID: s.id,
	})
}

// ReadData reads up to len(dst) bytes from channel ch, returning io.EOF once the
// peer half-closes ch and all queued bytes are drained.
func (s *Stream) ReadData(ctx context.Context, ch Channel, dst []byte) (int, error) {
	if int(ch) >= maxChannelsPerStream {
		return 0, fmt.Errorf("control: invalid data channel %d", ch)
	}
	if len(dst) == 0 {
		return 0, nil
	}
	for {
		s.rxMu.Lock()
		q := &s.queues[ch]
		if len(q.chunks) > 0 {
			n := copy(dst, q.chunks[0])
			if n == len(q.chunks[0]) {
				q.chunks[0] = nil
				q.chunks = q.chunks[1:]
				if len(q.chunks) == 0 {
					q.chunks = nil
				}
			} else {
				q.chunks[0] = q.chunks[0][n:]
			}
			q.buffered -= n
			s.rxTotal -= n
			s.rxConsumed += n
			var refill uint32
			if s.rxConsumed >= WindowRefillThreshold {
				refill = uint32(s.rxConsumed)
				s.rxConsumed = 0
			}
			s.rxMu.Unlock()
			if refill > 0 {
				s.sendWindowUpdate(refill)
			}
			return n, nil
		}
		if q.eof {
			err := s.err
			s.rxMu.Unlock()
			if err != nil && !errors.Is(err, ErrStreamClosed) {
				return 0, err
			}
			return 0, io.EOF
		}
		if s.err != nil {
			err := s.err
			s.rxMu.Unlock()
			return 0, err
		}
		waitCh := q.notify
		s.rxMu.Unlock()

		select {
		case <-waitCh:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			// Loop once more to drain any queued chunks or EOF before reporting error.
		}
	}
}

func (s *Stream) sendWindowUpdate(delta uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], delta)
	_ = s.conn.writeFrame(Frame{
		Type:     FrameWindowUpdate,
		StreamID: s.id,
		Payload:  payload[:],
	})
}

// SendEvent sends one typed JSON event frame on the stream.
func (s *Stream) SendEvent(ctx context.Context, eventType string, data any) error {
	return s.sendEvent(ctx, eventType, data, 0)
}

// SendFinalEvent sends one typed JSON event frame marked with FlagEndStream.
func (s *Stream) SendFinalEvent(ctx context.Context, eventType string, data any) error {
	return s.sendEvent(ctx, eventType, data, FlagEndStream)
}

func (s *Stream) sendEvent(ctx context.Context, eventType string, data any, flags FrameFlags) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return s.streamErr()
	default:
	}
	var raw json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("control: marshal event %q: %w", eventType, err)
		}
		raw = b
	}
	payload, err := json.Marshal(EventEnvelope{Type: eventType, Data: raw})
	if err != nil {
		return fmt.Errorf("control: marshal event envelope: %w", err)
	}
	return s.conn.writeFrame(Frame{
		Type:     FrameEvent,
		Flags:    flags,
		StreamID: s.id,
		Payload:  payload,
	})
}

// CloseEvents sends an empty FrameEvent with FlagEndStream so RecvEvent returns io.EOF.
func (s *Stream) CloseEvents() error {
	return s.conn.writeFrame(Frame{
		Type:     FrameEvent,
		Flags:    FlagEndStream,
		StreamID: s.id,
	})
}

// RecvEvent waits for the next event on the stream or returns io.EOF once closed.
func (s *Stream) RecvEvent(ctx context.Context) (EventEnvelope, error) {
	for {
		s.rxMu.Lock()
		if len(s.events) > 0 {
			ev := s.events[0]
			s.events[0] = EventEnvelope{}
			s.events = s.events[1:]
			if len(s.events) == 0 {
				s.events = nil
			}
			s.rxMu.Unlock()
			return ev, nil
		}
		if s.eventsEOF {
			err := s.err
			s.rxMu.Unlock()
			if err != nil && !errors.Is(err, ErrStreamClosed) {
				return EventEnvelope{}, err
			}
			return EventEnvelope{}, io.EOF
		}
		if s.err != nil {
			err := s.err
			s.rxMu.Unlock()
			return EventEnvelope{}, err
		}
		waitCh := s.eventNotify
		s.rxMu.Unlock()

		select {
		case <-waitCh:
		case <-ctx.Done():
			return EventEnvelope{}, ctx.Err()
		case <-s.done:
		}
	}
}

// ChannelReader adapts ReadData on one channel to io.Reader.
func (s *Stream) ChannelReader(ctx context.Context, ch Channel) io.Reader {
	return &streamChannelReader{ctx: ctx, stream: s, ch: ch}
}

// ChannelWriter adapts WriteData and CloseChannel on one channel to io.WriteCloser.
func (s *Stream) ChannelWriter(ctx context.Context, ch Channel, compress bool) io.WriteCloser {
	return &streamChannelWriter{ctx: ctx, stream: s, ch: ch, compress: compress}
}

type streamChannelReader struct {
	ctx    context.Context
	stream *Stream
	ch     Channel
}

func (r *streamChannelReader) Read(p []byte) (int, error) {
	return r.stream.ReadData(r.ctx, r.ch, p)
}

type streamChannelWriter struct {
	ctx      context.Context
	stream   *Stream
	ch       Channel
	compress bool
}

func (w *streamChannelWriter) Write(p []byte) (int, error) {
	return w.stream.writeData(w.ctx, w.ch, p, w.compress)
}

func (w *streamChannelWriter) Close() error {
	return w.stream.CloseChannel(w.ch)
}
