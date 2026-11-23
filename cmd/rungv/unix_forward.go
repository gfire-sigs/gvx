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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

const unixForwardHelperSubcmd = "__unix-forward-helper"

func init() {
	register(command{
		name:    "unix-forward",
		aliases: []string{"uf"},
		summary: "Forward guest Unix sockets to host Unix sockets over the control socket (alias: uf).",
		usage:   []string{"rungv unix-forward -S <socket>|-n <name> [--replace] GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600] ..."},
		run:     unixForwardSubcommand,
	})
}

func unixForwardSubcommand(ctx context.Context, args []string, streams cliIO) int {
	const cmdName = "unix-forward"
	fs := newImageFlagSet(cmdName, streams.stderr)
	target := addControlFlags(fs, 0)
	replace := fs.Bool("replace", false, "Replace an existing socket file at GUEST_PATH")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return controlUsageError(streams.stderr, cmdName, "specify at least one GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600]")
	}

	specs := make([]gvx.UnixForward, 0, fs.NArg())
	for _, raw := range fs.Args() {
		uf, err := gvx.ParseUnixForward(raw)
		if err != nil {
			return controlUsageError(streams.stderr, cmdName, "%v", err)
		}
		specs = append(specs, uf)
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer client.Close()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	recordErr := func(e error) {
		if e == nil || errors.Is(e, context.Canceled) || errors.Is(e, io.EOF) {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		errMu.Unlock()
		cancel()
	}

	opened := make([]*control.Stream, 0, len(specs))
	for _, spec := range specs {
		st, err := client.OpenStream(runCtx, control.MethodUnixForward, control.UnixForwardRequest{
			GuestPath: spec.GuestPath,
			UID:       spec.UID,
			GID:       spec.GID,
			Mode:      spec.Mode,
			Replace:   *replace,
		})
		if err != nil {
			for _, prev := range opened {
				prev.Cancel(nil)
			}
			return controlFail(streams.stderr, cmdName, err)
		}
		var resp control.UnixForwardResponse
		if err := st.WaitResponse(runCtx, &resp); err != nil {
			st.Cancel(nil)
			for _, prev := range opened {
				prev.Cancel(nil)
			}
			return controlFail(streams.stderr, cmdName, err)
		}
		opened = append(opened, st)
		_, _ = fmt.Fprintf(streams.stdout, "forwarding guest %s -> host %s\n", resp.GuestPath, spec.HostSocket)
	}

	for i, st := range opened {
		spec := specs[i]
		wg.Add(1)
		go func(st *control.Stream, uf gvx.UnixForward) {
			defer wg.Done()
			defer st.Close()
			var connWG sync.WaitGroup
			for {
				ev, err := st.RecvEvent(runCtx)
				if err != nil {
					recordErr(err)
					break
				}
				if ev.Type != "unix.accept" {
					continue
				}
				var acc control.UnixAcceptEvent
				if json.Unmarshal(ev.Data, &acc) != nil || acc.ConnID == 0 {
					continue
				}
				connWG.Add(1)
				go func(connID uint64) {
					defer connWG.Done()
					relayClientUnixAccept(runCtx, client, st, connID, uf.HostSocket)
				}(acc.ConnID)
			}
			connWG.Wait()
		}(st, spec)
	}

	select {
	case <-runCtx.Done():
	case <-client.Done():
		cancel()
	}
	for _, st := range opened {
		st.Cancel(nil)
	}
	wg.Wait()
	if firstErr != nil {
		return controlFail(streams.stderr, cmdName, firstErr)
	}
	return 0
}

func relayClientUnixAccept(ctx context.Context, client *control.Client, ctrlStream *control.Stream, connID uint64, hostSocket string) {
	sendReject := func(err error) {
		_ = ctrlStream.SendEvent(ctx, "unix.reject", control.UnixRejectEvent{
			ConnID: connID,
			Error:  err.Error(),
		})
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	var d net.Dialer
	hostConn, err := d.DialContext(dialCtx, "unix", hostSocket)
	cancel()
	if err != nil {
		sendReject(err)
		return
	}
	defer hostConn.Close()

	dataStream, err := client.OpenStream(ctx, control.MethodUnixAccept, control.UnixAcceptRequest{ConnID: connID})
	if err != nil {
		sendReject(err)
		return
	}
	defer dataStream.Close()
	if err := dataStream.WaitResponse(ctx, nil); err != nil {
		sendReject(err)
		return
	}

	stop := context.AfterFunc(ctx, func() { _ = hostConn.Close() })
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	// Host socket -> Guest stream
	go func() {
		defer wg.Done()
		w := dataStream.ChannelWriter(ctx, control.ChannelGeneric, false)
		_, _ = io.Copy(w, hostConn)
		_ = w.Close()
	}()
	// Guest stream -> Host socket
	go func() {
		defer wg.Done()
		_, _ = io.Copy(hostConn, dataStream.ChannelReader(ctx, control.ChannelGeneric))
		if cw, ok := hostConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// pipeConn adapts a read pipe and write pipe into a net.Conn for the
// pre-lockdown boot-time unix-forward helper.
type pipeConn struct {
	r       io.ReadCloser
	w       io.WriteCloser
	onClose func()
	closed  sync.Once
}

func (p *pipeConn) Read(b []byte) (int, error)       { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error)      { return p.w.Write(b) }
func (p *pipeConn) LocalAddr() net.Addr              { return pipeAddr("pipe") }
func (p *pipeConn) RemoteAddr() net.Addr             { return pipeAddr("pipe") }
func (p *pipeConn) SetDeadline(time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(time.Time) error { return nil }
func (p *pipeConn) Close() error {
	var err error
	p.closed.Do(func() {
		wErr := p.w.Close()
		rErr := p.r.Close()
		if p.onClose != nil {
			p.onClose()
		}
		err = errors.Join(wErr, rErr)
	})
	return err
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

// streamNetConn adapts a gvx-ctrl/2 data stream on ChannelGeneric into a net.Conn.
type streamNetConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	stream *control.Stream
	r      io.Reader
	w      io.WriteCloser
	closed sync.Once
}

func newStreamNetConn(parent context.Context, st *control.Stream) *streamNetConn {
	ctx, cancel := context.WithCancel(parent)
	return &streamNetConn{
		ctx:    ctx,
		cancel: cancel,
		stream: st,
		r:      st.ChannelReader(ctx, control.ChannelGeneric),
		w:      st.ChannelWriter(ctx, control.ChannelGeneric, false),
	}
}

func (c *streamNetConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *streamNetConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *streamNetConn) CloseWrite() error           { return c.w.Close() }
func (c *streamNetConn) LocalAddr() net.Addr         { return pipeAddr("unix-forward") }
func (c *streamNetConn) RemoteAddr() net.Addr        { return pipeAddr("unix-forward") }
func (c *streamNetConn) SetDeadline(time.Time) error { return nil }
func (c *streamNetConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *streamNetConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (c *streamNetConn) Close() error {
	c.closed.Do(func() {
		_ = c.w.Close()
		c.cancel()
		c.stream.Close()
	})
	return nil
}

// singleConnListener yields one pre-established net.Conn and then blocks until Close.
type singleConnListener struct {
	mu     sync.Mutex
	conn   net.Conn
	closed chan struct{}
	once   sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return pipeAddr("unix-forward-helper") }

// startBootUnixForwardHelper spawns an unlocked helper child before host
// lockdown that dials only the exact pre-configured host Unix socket paths on
// behalf of the locked sandbox over a pre-opened stdin/stdout pipe pair.
func startBootUnixForwardHelper(ctx context.Context, forwards []gvx.UnixForward) (func(), error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate rungv executable for unix-forward helper: %w", err)
	}
	helperArgs := make([]string, 0, len(forwards)+1)
	helperArgs = append(helperArgs, unixForwardHelperSubcmd)
	for _, uf := range forwards {
		helperArgs = append(helperArgs, uf.HostSocket)
	}
	cmd := exec.Command(exe, helperArgs...)
	inPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("unix-forward helper stdin pipe: %w", err)
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = inPipe.Close()
		return nil, fmt.Errorf("unix-forward helper stdout pipe: %w", err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = inPipe.Close()
		_ = outPipe.Close()
		return nil, fmt.Errorf("start unix-forward helper: %w", err)
	}

	pc := &pipeConn{r: outPipe, w: inPipe}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	client, err := control.DialConn(dialCtx, pc, control.DialOptions{
		ClientName:       "rungv-boot-unix-forward",
		HandshakeTimeout: 10 * time.Second,
	})
	cancel()
	if err != nil {
		_ = pc.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("handshake with unix-forward helper: %w", err)
	}

	for i := range forwards {
		idx := uint64(i + 1)
		forwards[i].Dial = func(dctx context.Context) (net.Conn, error) {
			st, err := client.OpenStream(dctx, control.MethodUnixAccept, control.UnixAcceptRequest{ConnID: idx})
			if err != nil {
				return nil, err
			}
			if err := st.WaitResponse(dctx, nil); err != nil {
				st.Close()
				return nil, err
			}
			return newStreamNetConn(context.Background(), st), nil
		}
	}

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = client.Close()
			_ = pc.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = cmd.Wait()
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		})
	}
	return stop, nil
}

type unixForwardHelperHandler struct {
	sockets []string
}

func (h *unixForwardHelperHandler) HandleLegacyCheckpoint(context.Context, control.LegacyCheckpointRequest) error {
	return control.NewError(control.CodeUnsupported, "legacy checkpoint unsupported on helper")
}

func (h *unixForwardHelperHandler) HandleStream(ctx context.Context, stream *control.Stream, req control.RequestEnvelope, _ []int) error {
	if req.Method != control.MethodUnixAccept {
		return control.NewErrorf(control.CodeUnsupported, "unsupported helper method %q", req.Method)
	}
	var p control.UnixAcceptRequest
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return control.NewErrorf(control.CodeInvalidArgument, "decode params: %v", err)
	}
	if p.ConnID == 0 || p.ConnID > uint64(len(h.sockets)) {
		return control.NewErrorf(control.CodeInvalidArgument, "invalid socket index %d", p.ConnID)
	}
	hostSocket := h.sockets[p.ConnID-1]
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	var d net.Dialer
	hostConn, err := d.DialContext(dialCtx, "unix", hostSocket)
	cancel()
	if err != nil {
		return control.NewErrorf(control.CodeNotFound, "dial host unix socket %q: %v", hostSocket, err)
	}
	defer hostConn.Close()

	if err := stream.SendResponse(map[string]any{}); err != nil {
		return err
	}

	stop := context.AfterFunc(ctx, func() { _ = hostConn.Close() })
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w := stream.ChannelWriter(ctx, control.ChannelGeneric, false)
		_, _ = io.Copy(w, hostConn)
		_ = w.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(hostConn, stream.ChannelReader(ctx, control.ChannelGeneric))
		if cw, ok := hostConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
	return nil
}

// runUnixForwardHelper serves dialed connections to the pre-configured host
// Unix socket paths over stdin/stdout until the parent closes the pipe.
func runUnixForwardHelper(ctx context.Context, sockets []string, stdin io.Reader, stdout io.Writer) int {
	inCloser, ok := stdin.(io.ReadCloser)
	if !ok {
		inCloser = io.NopCloser(stdin)
	}
	outCloser, ok := stdout.(io.WriteCloser)
	if !ok {
		outCloser = nopWriteCloser{stdout}
	}
	pc := &pipeConn{r: inCloser, w: outCloser}
	ln := newSingleConnListener(pc)
	pc.onClose = func() { _ = ln.Close() }
	srv := control.NewServer(ln, control.ServerConfig{
		SandboxID:      "unix-forward-helper",
		Capabilities:   []string{control.CapUnixForward},
		MaxConnections: 1,
		Handler:        &unixForwardHelperHandler{sockets: sockets},
	})
	_ = srv.Serve(ctx)
	return 0
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
