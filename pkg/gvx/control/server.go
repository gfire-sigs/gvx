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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

// Handler dispatches authenticated control RPC requests for one sandbox.
type Handler interface {
	// HandleStream serves one v2 RPC stream. Ownership of fds transfers to
	// HandleStream, which must close every descriptor when finished.
	HandleStream(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error
	// HandleLegacyCheckpoint serves a v1 single-JSON checkpoint request.
	HandleLegacyCheckpoint(ctx context.Context, req LegacyCheckpointRequest) error
}

// ServerConfig configures a Server instance.
type ServerConfig struct {
	SandboxID        string
	Token            string
	Capabilities     []string
	AllowFDs         bool
	MaxConnections   int
	MaxFrameBytes    int
	HandshakeTimeout time.Duration
	Handler          Handler
}

// Server accepts v2 framed control connections and legacy v1 JSON checkpoint
// requests on a single net.Listener.
type Server struct {
	cfg      ServerConfig
	listener net.Listener

	sem chan struct{}

	mu      sync.Mutex
	conns   map[*Conn]struct{}
	rawConn map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup
}

// NewServer constructs a control server bound to ln.
func NewServer(ln net.Listener, cfg ServerConfig) *Server {
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 64
	}
	if cfg.MaxFrameBytes <= 0 || cfg.MaxFrameBytes > AbsoluteMaxFrameBytes {
		cfg.MaxFrameBytes = DefaultMaxFrameBytes
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	return &Server{
		cfg:      cfg,
		listener: ln,
		sem:      make(chan struct{}, cfg.MaxConnections),
		conns:    make(map[*Conn]struct{}),
		rawConn:  make(map[net.Conn]struct{}),
	}
}

// Serve accepts connections until ctx is canceled or Close/Shutdown is called.
func (s *Server) Serve(ctx context.Context) error {
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-serveDone:
		}
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case s.sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-s.sem
			_ = conn.Close()
			return nil
		}
		s.rawConn[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		go func(nc net.Conn) {
			defer func() {
				s.mu.Lock()
				delete(s.rawConn, nc)
				s.mu.Unlock()
				<-s.sem
				s.wg.Done()
			}()
			s.serveConn(ctx, nc)
		}(conn)
	}
}

// Shutdown stops accepting new connections, sends GOAWAY to active v2 peers,
// closes idle connections, and waits up to ctx for in-flight RPCs to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	raws := make([]net.Conn, 0, len(s.rawConn))
	for rc := range s.rawConn {
		raws = append(raws, rc)
	}
	s.mu.Unlock()

	_ = s.listener.Close()

	for _, c := range conns {
		_ = c.SendGoAway("sandbox exiting")
		if c.activeStreams() == 0 {
			_ = c.Close()
		}
	}
	// Close connections still stuck in pre-auth handshake immediately.
	for _, rc := range raws {
		_ = rc.SetDeadline(time.Now())
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		for _, c := range conns {
			_ = c.Close()
		}
		for _, rc := range raws {
			_ = rc.Close()
		}
		<-done
		return ctx.Err()
	}
}

// Close closes the listener and waits briefly for connections to exit.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.Shutdown(ctx)
}

func (s *Server) serveConn(ctx context.Context, nc net.Conn) {
	if err := VerifyPeerCredentials(nc); err != nil {
		_ = nc.Close()
		return
	}
	_ = nc.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	br := bufio.NewReaderSize(nc, 4096)
	first, err := br.Peek(1)
	if err != nil {
		_ = nc.Close()
		return
	}
	if first[0] == '{' {
		s.serveLegacyV1(ctx, nc, br)
		return
	}
	if first[0] != Preface[0] {
		_ = nc.Close()
		return
	}
	var magic [4]byte
	if _, err := io.ReadFull(br, magic[:]); err != nil || string(magic[:]) != Preface {
		_ = nc.Close()
		return
	}

	// Drain any extra buffered bytes from bufio.Reader so subsequent direct reads
	// on nc stay aligned for SCM_RIGHTS.
	var prefix []byte
	if buffered := br.Buffered(); buffered > 0 {
		prefix = make([]byte, buffered)
		if _, err := io.ReadFull(br, prefix); err != nil {
			_ = nc.Close()
			return
		}
	}
	pr := &prefixReader{prefix: prefix, conn: nc}

	helloFrame, err := ReadFrame(pr, HandshakeMaxFrameBytes)
	if err != nil || helloFrame.Type != FrameHello || helloFrame.StreamID != 0 {
		_ = nc.Close()
		return
	}
	var helloReq HelloRequest
	if err := json.Unmarshal(helloFrame.Payload, &helloReq); err != nil {
		s.writeHelloFailure(nc, NewError(CodeInvalidArgument, "invalid hello payload"))
		_ = nc.Close()
		return
	}
	if helloReq.Version != ProtocolVersion {
		s.writeHelloFailure(nc, NewErrorf(CodeUnsupported, "unsupported control protocol version %d (want %d)", helloReq.Version, ProtocolVersion))
		_ = nc.Close()
		return
	}
	if !TokenMatches(s.cfg.Token, helloReq.Token) {
		s.writeHelloFailure(nc, NewError(CodeUnauthorized, "unauthorized control token"))
		_ = nc.Close()
		return
	}

	_, isUnix := nc.(*net.UnixConn)
	allowFDs := s.cfg.AllowFDs && isUnix && supportsControlFDs(runtime.GOOS)
	features := []string{"zstd"}
	if allowFDs {
		features = append(features, "scm_rights")
	}
	helloResp := HelloResponse{
		OK:            true,
		Version:       ProtocolVersion,
		SandboxID:     s.cfg.SandboxID,
		MaxFrameBytes: s.cfg.MaxFrameBytes,
		Capabilities:  s.cfg.Capabilities,
		Features:      features,
	}
	respBytes, err := json.Marshal(helloResp)
	if err != nil {
		_ = nc.Close()
		return
	}
	if err := WriteFrame(nc, Frame{
		Type:     FrameHello,
		StreamID: 0,
		Payload:  respBytes,
	}, s.cfg.MaxFrameBytes); err != nil {
		_ = nc.Close()
		return
	}

	// Clear handshake deadline once authenticated.
	_ = nc.SetDeadline(time.Time{})

	var c *Conn
	c = newConn(nc, pr.prefix, s.cfg.MaxFrameBytes, true, allowFDs, func(req incomingRequest) {
		c.inFlightWG.Add(1)
		go func() {
			defer c.inFlightWG.Done()
			s.dispatchStream(ctx, req)
		}()
	})

	s.mu.Lock()
	delete(s.rawConn, nc)
	if s.closed {
		s.mu.Unlock()
		_ = c.Close()
		return
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()

	c.startReadLoop()
	<-c.Done()
	c.inFlightWG.Wait()
}

func (s *Server) writeHelloFailure(nc net.Conn, pe *ProtoError) {
	payload, err := json.Marshal(HelloResponse{
		OK:      false,
		Version: ProtocolVersion,
		Error:   pe,
	})
	if err != nil {
		return
	}
	_ = WriteFrame(nc, Frame{
		Type:     FrameHello,
		StreamID: 0,
		Payload:  payload,
	}, HandshakeMaxFrameBytes)
}

func (s *Server) dispatchStream(serverCtx context.Context, req incomingRequest) {
	stream := req.stream
	defer stream.Close()

	if !MethodAllowed(req.env.Method, s.cfg.Capabilities) {
		closeFDs(req.fds)
		_ = stream.SendError(NewErrorf(CodeForbiddenByPolicy, "method %q is disabled by sandbox policy", req.env.Method))
		return
	}
	if s.cfg.Handler == nil {
		closeFDs(req.fds)
		_ = stream.SendError(NewError(CodeInternal, "control handler not configured"))
		return
	}

	// Tie handler context to both serverCtx and stream cancellation.
	hctx, cancel := context.WithCancel(serverCtx)
	defer cancel()
	go func() {
		select {
		case <-stream.Context().Done():
			cancel()
		case <-hctx.Done():
		}
	}()

	err := s.cfg.Handler.HandleStream(hctx, stream, req.env, req.fds)
	if err != nil {
		if !stream.respSent.Load() {
			_ = stream.SendError(err)
		} else {
			stream.Cancel(err)
		}
		return
	}
	if !stream.respSent.Load() {
		_ = stream.Reply(nil)
	}
}

func (s *Server) serveLegacyV1(ctx context.Context, nc net.Conn, br *bufio.Reader) {
	defer nc.Close()
	writeResp := func(ok bool, msg string) {
		b, _ := json.Marshal(LegacyCheckpointResponse{OK: ok, Error: msg})
		b = append(b, '\n')
		_, _ = nc.Write(b)
	}
	var req LegacyCheckpointRequest
	dec := json.NewDecoder(io.LimitReader(br, HandshakeMaxFrameBytes))
	if err := dec.Decode(&req); err != nil {
		writeResp(false, fmt.Sprintf("decode request: %v", err))
		return
	}
	if !TokenMatches(s.cfg.Token, req.Token) {
		writeResp(false, "unauthorized")
		return
	}
	if !MethodAllowed(MethodCheckpoint, s.cfg.Capabilities) {
		writeResp(false, "checkpoint is disabled by sandbox policy")
		return
	}
	if s.cfg.Handler == nil {
		writeResp(false, "control handler not configured")
		return
	}
	// Handshake is complete; keep the response writable during graceful shutdown.
	s.mu.Lock()
	delete(s.rawConn, nc)
	s.mu.Unlock()
	_ = nc.SetDeadline(time.Time{})
	if err := s.cfg.Handler.HandleLegacyCheckpoint(ctx, req); err != nil {
		writeResp(false, err.Error())
		return
	}
	writeResp(true, "")
}

func supportsControlFDs(goos string) bool {
	return goos == "linux" || goos == "android" || goos == "darwin"
}
