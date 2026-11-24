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

package gvx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/waiter"
)

const (
	defaultUnixForwardMode   = 0o666
	maxPendingUnixConns      = 64
	pendingUnixClaimTimeout  = 15 * time.Second
	unixEndpointRelayBufSize = 32 * 1024
)

var errNotUnixSocket = errors.New("guest path is not a Unix socket")

type activeUnixForward struct {
	guestPath string
	ep        transport.Endpoint
	cancel    context.CancelFunc
	done      chan struct{}
}

type pendingUnixConn struct {
	fwd       *activeUnixForward
	ownerConn *control.Conn
	ep        transport.Endpoint
	k         *kernel.Kernel
	timer     *time.Timer
}

// unixEndpointConn adapts a connected Sentry Unix stream transport.Endpoint to
// an io.ReadWriteCloser with half-close support. epMu serializes ep.Close
// against concurrent non-blocking endpoint calls.
type unixEndpointConn struct {
	ctx      context.Context
	sctx     gvcontext.Context
	epMu     sync.RWMutex
	ep       transport.Endpoint
	isClosed bool
	closed   sync.Once
	done     chan struct{}
}

func newUnixEndpointConn(ctx context.Context, sctx gvcontext.Context, ep transport.Endpoint) *unixEndpointConn {
	return &unixEndpointConn{
		ctx:  ctx,
		sctx: sctx,
		ep:   ep,
		done: make(chan struct{}),
	}
}

func (c *unixEndpointConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var (
		we  waiter.Entry
		ch  chan struct{}
		reg bool
	)
	defer func() {
		if reg {
			c.epMu.RLock()
			if !c.isClosed {
				c.ep.EventUnregister(&we)
			}
			c.epMu.RUnlock()
		}
	}()
	for {
		c.epMu.RLock()
		if c.isClosed {
			c.epMu.RUnlock()
			return 0, net.ErrClosed
		}
		out, notify, serr := c.ep.RecvMsg(c.sctx, [][]byte{p}, transport.RecvArgs{})
		c.epMu.RUnlock()
		if notify != nil {
			notify()
		}
		if out.Control.Rights != nil {
			out.Control.Rights.Release(c.sctx)
		}
		for _, unused := range out.UnusedRights {
			unused.Release(c.sctx)
		}
		if serr == nil {
			if out.RecvLen == 0 {
				return 0, io.EOF
			}
			return int(out.RecvLen), nil
		}
		if serr != syserr.ErrWouldBlock {
			if serr == syserr.ErrClosedForReceive || serr == syserr.ErrConnectionReset {
				return 0, io.EOF
			}
			return 0, serr.ToError()
		}
		if !reg {
			we, ch = waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp | waiter.EventRdHUp | waiter.EventErr)
			c.epMu.RLock()
			if c.isClosed {
				c.epMu.RUnlock()
				return 0, net.ErrClosed
			}
			c.ep.EventRegister(&we)
			c.epMu.RUnlock()
			reg = true
			continue
		}
		select {
		case <-ch:
		case <-c.done:
			return 0, net.ErrClosed
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		}
	}
}

func (c *unixEndpointConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var (
		we    waiter.Entry
		ch    chan struct{}
		reg   bool
		total int
	)
	defer func() {
		if reg {
			c.epMu.RLock()
			if !c.isClosed {
				c.ep.EventUnregister(&we)
			}
			c.epMu.RUnlock()
		}
	}()
	for total < len(p) {
		c.epMu.RLock()
		if c.isClosed {
			c.epMu.RUnlock()
			return total, net.ErrClosed
		}
		n, notify, serr := c.ep.SendMsg(c.sctx, [][]byte{p[total:]}, transport.ControlMessages{}, nil)
		c.epMu.RUnlock()
		if notify != nil {
			notify()
		}
		if n > 0 {
			total += int(n)
		}
		if serr == nil {
			continue
		}
		if serr != syserr.ErrWouldBlock {
			return total, serr.ToError()
		}
		if !reg {
			we, ch = waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
			c.epMu.RLock()
			if c.isClosed {
				c.epMu.RUnlock()
				return total, net.ErrClosed
			}
			c.ep.EventRegister(&we)
			c.epMu.RUnlock()
			reg = true
			continue
		}
		select {
		case <-ch:
		case <-c.done:
			return total, net.ErrClosed
		case <-c.ctx.Done():
			return total, c.ctx.Err()
		}
	}
	return total, nil
}

func (c *unixEndpointConn) CloseWrite() error {
	c.epMu.RLock()
	defer c.epMu.RUnlock()
	if c.isClosed {
		return nil
	}
	if serr := c.ep.Shutdown(tcpip.ShutdownWrite); serr != nil {
		return serr.ToError()
	}
	return nil
}

func (c *unixEndpointConn) Close() error {
	c.closed.Do(func() {
		close(c.done)
		c.epMu.Lock()
		c.isClosed = true
		c.ep.Close(c.sctx)
		c.epMu.Unlock()
	})
	return nil
}

func bindGuestUnixListener(
	sctx gvcontext.Context,
	k *kernel.Kernel,
	creds *auth.Credentials,
	root vfs.VirtualDentry,
	mntns *vfs.MountNamespace,
	guestPath string,
	uid, gid, mode uint32,
	replace bool,
) (transport.Endpoint, error) {
	if mode == 0 {
		mode = defaultUnixForwardMode
	}
	mode &= 0o777
	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	vfsObj := k.VFS()

	parent := path.Dir(guestPath)
	if parent != "/" && parent != "." {
		if err := vfsEnsureDirAll(sctxWithRoot, vfsObj, creds, root, parent, 0o755); err != nil {
			return nil, fmt.Errorf("create parent directory %q: %w", parent, err)
		}
	}
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               makeFPath(guestPath),
		FollowFinalSymlink: false,
	}
	if replace {
		st, err := vfsObj.StatAt(sctxWithRoot, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
		if err == nil {
			if st.Mode&linux.S_IFMT != linux.S_IFSOCK {
				return nil, fmt.Errorf("%w: %q", errNotUnixSocket, guestPath)
			}
			if err := vfsObj.UnlinkAt(sctxWithRoot, creds, &pop); err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
				return nil, fmt.Errorf("remove existing socket %q: %w", guestPath, err)
			}
		} else if !linuxerr.Equals(linuxerr.ENOENT, err) {
			return nil, fmt.Errorf("stat existing path %q: %w", guestPath, err)
		}
	}

	ep := transport.NewConnectioned(sctx, linux.SOCK_STREAM, k)
	bep, ok := ep.(transport.BoundEndpoint)
	if !ok {
		ep.Close(sctx)
		return nil, errors.New("unix transport endpoint does not implement BoundEndpoint")
	}
	if serr := ep.Bind(transport.Address{Addr: guestPath}); serr != nil {
		ep.Close(sctx)
		return nil, fmt.Errorf("bind unix endpoint %q: %w", guestPath, serr.ToError())
	}
	if serr := ep.Listen(sctx, 128); serr != nil {
		ep.Close(sctx)
		return nil, fmt.Errorf("listen unix endpoint %q: %w", guestPath, serr.ToError())
	}
	if err := vfsObj.MknodAt(sctxWithRoot, creds, &pop, &vfs.MknodOptions{
		Mode:     linux.FileMode(linux.S_IFSOCK | mode),
		Endpoint: bep,
	}); err != nil {
		ep.Close(sctx)
		return nil, err
	}
	if err := vfsObj.SetStatAt(sctxWithRoot, creds, &pop, &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_UID | linux.STATX_GID | linux.STATX_MODE,
			UID:  uid,
			GID:  gid,
			Mode: uint16(mode),
		},
	}); err != nil {
		_ = vfsObj.UnlinkAt(sctxWithRoot, creds, &pop)
		ep.Close(sctx)
		return nil, fmt.Errorf("set unix socket ownership/mode on %q: %w", guestPath, err)
	}
	return ep, nil
}

func (s *Sandbox) unlinkGuestUnixPath(k *kernel.Kernel, guestPath string) {
	if k == nil {
		return
	}
	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)
	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath)}
	_ = k.VFS().UnlinkAt(sctxWithRoot, creds, &pop)
}

func acceptGuestUnixLoop(ctx context.Context, sctx gvcontext.Context, ep transport.Endpoint, onAccept func(transport.Endpoint)) {
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp | waiter.EventErr)
	ep.EventRegister(&we)
	defer ep.EventUnregister(&we)

	for {
		connEP, serr := ep.Accept(sctx, nil)
		if serr == nil {
			onAccept(connEP)
			continue
		}
		if serr != syserr.ErrWouldBlock {
			return
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return
		}
	}
}

func relayUnixConnPair(ctx context.Context, guestConn *unixEndpointConn, hostConn net.Conn) {
	defer func() {
		_ = guestConn.Close()
		_ = hostConn.Close()
	}()
	stop := context.AfterFunc(ctx, func() {
		_ = guestConn.Close()
		_ = hostConn.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	wg.Add(2)
	// Guest -> Host
	go func() {
		defer wg.Done()
		buf := make([]byte, unixEndpointRelayBufSize)
		_, _ = io.CopyBuffer(hostConn, guestConn, buf)
		if cw, ok := hostConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	// Host -> Guest
	go func() {
		defer wg.Done()
		buf := make([]byte, unixEndpointRelayBufSize)
		_, _ = io.CopyBuffer(guestConn, hostConn, buf)
		_ = guestConn.CloseWrite()
	}()
	wg.Wait()
}

// startBootUnixForwards binds all boot-time Config.UnixForwards inside the
// guest VFS before PID 1 starts and launches their accept loops.
func (s *Sandbox) startBootUnixForwards(ctx context.Context, k *kernel.Kernel, creds *auth.Credentials, root vfs.VirtualDentry, mntns *vfs.MountNamespace) error {
	if len(s.cfg.UnixForwards) == 0 {
		return nil
	}
	sctx := k.SupervisorContext()
	for _, uf := range s.cfg.UnixForwards {
		dialFn := uf.Dial
		if dialFn == nil {
			hostSock := uf.HostSocket
			dialFn = func(dctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dctx, "unix", hostSock)
			}
		}
		ep, err := bindGuestUnixListener(sctx, k, creds, root, mntns, uf.GuestPath, uf.UID, uf.GID, uf.Mode, true)
		if err != nil {
			s.closeUnixForwards()
			return fmt.Errorf("gvx: bind unix forward %q: %w", uf.GuestPath, err)
		}
		fwdCtx, cancel := context.WithCancel(ctx)
		fwd := &activeUnixForward{
			guestPath: uf.GuestPath,
			ep:        ep,
			cancel:    cancel,
			done:      make(chan struct{}),
		}
		s.unixFwdMu.Lock()
		if s.unixClosed {
			s.unixFwdMu.Unlock()
			cancel()
			ep.Close(sctx)
			close(fwd.done)
			return control.NewError(control.CodeSandboxExiting, "sandbox is shutting down")
		}
		if s.unixForwards == nil {
			s.unixForwards = make(map[string]*activeUnixForward)
		}
		s.unixForwards[uf.GuestPath] = fwd
		s.unixFwdMu.Unlock()

		go func(f *activeUnixForward, dial func(context.Context) (net.Conn, error)) {
			defer func() {
				s.unixFwdMu.Lock()
				if s.unixForwards[f.guestPath] == f {
					delete(s.unixForwards, f.guestPath)
				}
				s.unixFwdMu.Unlock()
				close(f.done)
			}()
			defer f.ep.Close(sctx)
			var connWG sync.WaitGroup
			acceptGuestUnixLoop(fwdCtx, sctx, f.ep, func(connEP transport.Endpoint) {
				connWG.Add(1)
				go func() {
					defer connWG.Done()
					guestConn := newUnixEndpointConn(fwdCtx, sctx, connEP)
					dialCtx, dialCancel := context.WithTimeout(fwdCtx, 10*time.Second)
					hostConn, err := dial(dialCtx)
					dialCancel()
					if err != nil {
						_ = guestConn.Close()
						return
					}
					relayUnixConnPair(fwdCtx, guestConn, hostConn)
				}()
			})
			connWG.Wait()
		}(fwd, dialFn)
	}
	return nil
}

func (s *Sandbox) closeUnixForwards() {
	s.unixFwdMu.Lock()
	if !s.unixClosed {
		s.unixClosed = true
		if s.unixCloseCh != nil {
			close(s.unixCloseCh)
		}
	}
	fwds := make([]*activeUnixForward, 0, len(s.unixForwards))
	for _, f := range s.unixForwards {
		fwds = append(fwds, f)
	}
	pending := make([]*pendingUnixConn, 0, len(s.pendingUnixConns))
	for id, p := range s.pendingUnixConns {
		pending = append(pending, p)
		delete(s.pendingUnixConns, id)
	}
	s.unixFwdMu.Unlock()

	for _, p := range pending {
		if p.timer != nil {
			p.timer.Stop()
		}
		if p.ep != nil && p.k != nil {
			p.ep.Close(p.k.SupervisorContext())
		}
	}
	for _, f := range fwds {
		if f.cancel != nil {
			f.cancel()
		}
		if f.done != nil {
			<-f.done
		}
	}
	s.unixRelayWG.Wait()
}

func (s *Sandbox) handleUnixForward(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.UnixForwardRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	guestPath := strings.TrimSpace(req.GuestPath)
	if err := validateUnixForwardGuestPath(guestPath); err != nil {
		return control.NewErrorf(control.CodeInvalidArgument, "invalid guest_path %q: %v", req.GuestPath, err)
	}
	if req.Mode > 0o777 {
		return control.NewErrorf(control.CodeInvalidArgument, "mode %#o out of range [0, 0777]", req.Mode)
	}

	if _, _, err := s.activeKernelChecked(ctx); err != nil {
		return err
	}

	s.opMu.RLock()
	opLocked := true
	unlockOp := func() {
		if opLocked {
			opLocked = false
			s.opMu.RUnlock()
		}
	}
	defer unlockOp()

	k, _, err := s.activeKernelNow()
	if err != nil {
		return err
	}

	s.unixFwdMu.Lock()
	if s.unixClosed {
		s.unixFwdMu.Unlock()
		return control.NewError(control.CodeSandboxExiting, "sandbox is shutting down")
	}
	if _, exists := s.unixForwards[guestPath]; exists {
		s.unixFwdMu.Unlock()
		return control.NewErrorf(control.CodeAlreadyExists, "unix forward already active at %q", guestPath)
	}
	if s.unixForwards == nil {
		s.unixForwards = make(map[string]*activeUnixForward)
	}
	// Reserve guestPath under lock before binding.
	fwdCtx, cancel := context.WithCancel(ctx)
	fwd := &activeUnixForward{
		guestPath: guestPath,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	s.unixForwards[guestPath] = fwd
	s.unixFwdMu.Unlock()

	cleanupReservation := func() {
		cancel()
		s.unixFwdMu.Lock()
		if s.unixForwards[guestPath] == fwd {
			delete(s.unixForwards, guestPath)
		}
		s.unixFwdMu.Unlock()
		close(fwd.done)
	}

	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		cleanupReservation()
		return err
	}
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	ep, bindErr := bindGuestUnixListener(sctx, k, creds, root, mntns, guestPath, req.UID, req.GID, req.Mode, req.Replace)
	root.DecRef(sctx)
	mntns.DecRef(sctx)
	if bindErr != nil {
		cleanupReservation()
		if errors.Is(bindErr, errNotUnixSocket) {
			return control.NewErrorf(control.CodeAlreadyExists, "guest path %q exists and is not a Unix socket (refusing to replace)", guestPath)
		}
		if linuxerr.Equals(linuxerr.EEXIST, bindErr) {
			return control.NewErrorf(control.CodeAlreadyExists, "guest path %q already exists (pass replace=true to overwrite)", guestPath)
		}
		return control.NewErrorf(control.CodeInternal, "bind guest unix socket %q: %v", guestPath, bindErr)
	}
	fwd.ep = ep

	if err := stream.SendResponse(control.UnixForwardResponse{GuestPath: guestPath}); err != nil {
		ep.Close(sctx)
		s.unlinkGuestUnixPath(k, guestPath)
		cleanupReservation()
		return err
	}

	// Release opMu before entering the long-lived accept loop so pause,
	// checkpoint, and other lifecycle RPCs never block on an active forward.
	unlockOp()

	s.emitEvent("unix_forward", "add", map[string]string{"guest_path": guestPath})

	defer func() {
		cancel()
		s.unixFwdMu.Lock()
		var stale []*pendingUnixConn
		for id, p := range s.pendingUnixConns {
			if p.fwd == fwd {
				stale = append(stale, p)
				delete(s.pendingUnixConns, id)
			}
		}
		s.unixFwdMu.Unlock()

		for _, p := range stale {
			if p.timer != nil {
				p.timer.Stop()
			}
			p.ep.Close(sctx)
		}
		ep.Close(sctx)

		// Unlink only while the bound kernel is still active, and hold the
		// guestPath reservation in s.unixForwards until unlink completes so a
		// new forward at the same path cannot race ahead of cleanup.
		s.opMu.RLock()
		s.mu.Lock()
		sameKernel := s.activeKernel == k
		s.mu.Unlock()
		if sameKernel {
			s.unlinkGuestUnixPath(k, guestPath)
		}
		s.opMu.RUnlock()

		s.unixFwdMu.Lock()
		if s.unixForwards[guestPath] == fwd {
			delete(s.unixForwards, guestPath)
		}
		s.unixFwdMu.Unlock()
		close(fwd.done)
		s.emitEvent("unix_forward", "remove", map[string]string{"guest_path": guestPath})
	}()

	// Read client events (unix.reject or stream EOF/cancel) in background.
	go func() {
		defer cancel()
		for {
			ev, err := stream.RecvEvent(fwdCtx)
			if err != nil {
				return
			}
			if ev.Type != "unix.reject" {
				continue
			}
			var rej control.UnixRejectEvent
			if json.Unmarshal(ev.Data, &rej) != nil || rej.ConnID == 0 {
				continue
			}
			if p := s.claimPendingUnixConnForForward(rej.ConnID, fwd); p != nil {
				p.ep.Close(sctx)
			}
		}
	}()

	// Stop when sandbox exits as well.
	go func() {
		select {
		case <-s.runDone:
			cancel()
		case <-fwdCtx.Done():
		}
	}()

	ownerConn := stream.Conn()
	acceptGuestUnixLoop(fwdCtx, sctx, ep, func(connEP transport.Endpoint) {
		connID := s.nextUnixConnID.Add(1)
		p := &pendingUnixConn{fwd: fwd, ownerConn: ownerConn, ep: connEP, k: k}
		s.unixFwdMu.Lock()
		if s.unixClosed || len(s.pendingUnixConns) >= maxPendingUnixConns {
			s.unixFwdMu.Unlock()
			connEP.Close(sctx)
			return
		}
		if s.pendingUnixConns == nil {
			s.pendingUnixConns = make(map[uint64]*pendingUnixConn)
		}
		p.timer = time.AfterFunc(pendingUnixClaimTimeout, func() {
			if expired := s.claimPendingUnixConnForForward(connID, fwd); expired != nil {
				expired.ep.Close(sctx)
			}
		})
		s.pendingUnixConns[connID] = p
		s.unixFwdMu.Unlock()

		if err := stream.SendEvent(fwdCtx, "unix.accept", control.UnixAcceptEvent{ConnID: connID}); err != nil {
			if dropped := s.claimPendingUnixConnForForward(connID, fwd); dropped != nil {
				dropped.ep.Close(sctx)
			}
			cancel()
		}
	})
	_ = stream.CloseEvents()
	return nil
}

func (s *Sandbox) claimPendingUnixConnForForward(connID uint64, fwd *activeUnixForward) *pendingUnixConn {
	s.unixFwdMu.Lock()
	p := s.pendingUnixConns[connID]
	if p == nil || p.fwd != fwd {
		s.unixFwdMu.Unlock()
		return nil
	}
	delete(s.pendingUnixConns, connID)
	s.unixFwdMu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	return p
}

func (s *Sandbox) claimPendingUnixConnForAccept(connID uint64, conn *control.Conn) *pendingUnixConn {
	s.unixFwdMu.Lock()
	if s.unixClosed {
		s.unixFwdMu.Unlock()
		return nil
	}
	p := s.pendingUnixConns[connID]
	if p == nil || p.ownerConn != conn {
		s.unixFwdMu.Unlock()
		return nil
	}
	delete(s.pendingUnixConns, connID)
	s.unixRelayWG.Add(1)
	s.unixFwdMu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	return p
}

func (s *Sandbox) handleUnixAccept(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.UnixAcceptRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if req.ConnID == 0 {
		return control.NewError(control.CodeInvalidArgument, "conn_id must be non-zero")
	}
	p := s.claimPendingUnixConnForAccept(req.ConnID, stream.Conn())
	if p == nil {
		return control.NewErrorf(control.CodeNotFound, "pending unix connection %d not found or expired", req.ConnID)
	}
	defer s.unixRelayWG.Done()

	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	sctx := p.k.SupervisorContext()
	guestConn := newUnixEndpointConn(relayCtx, sctx, p.ep)
	defer guestConn.Close()

	if err := stream.SendResponse(map[string]any{}); err != nil {
		return err
	}

	stopDone := make(chan struct{})
	defer close(stopDone)
	go func() {
		select {
		case <-relayCtx.Done():
			_ = guestConn.Close()
		case <-s.unixCloseCh:
			relayCancel()
			_ = guestConn.Close()
		case <-stopDone:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	// Client (host socket) -> Guest Unix socket
	go func() {
		defer wg.Done()
		buf := make([]byte, unixEndpointRelayBufSize)
		_, _ = io.CopyBuffer(guestConn, stream.ChannelReader(relayCtx, control.ChannelGeneric), buf)
		_ = guestConn.CloseWrite()
	}()
	// Guest Unix socket -> Client (host socket)
	go func() {
		defer wg.Done()
		w := stream.ChannelWriter(relayCtx, control.ChannelGeneric, false)
		buf := make([]byte, unixEndpointRelayBufSize)
		_, _ = io.CopyBuffer(w, guestConn, buf)
		_ = w.Close()
	}()
	wg.Wait()
	return nil
}
