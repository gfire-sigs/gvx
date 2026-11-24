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

//go:build darwin

package gpurender

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/fd"
)

const deadlineTick = 100 * time.Millisecond

// Client is the connection to one renderer process. All methods are safe for
// concurrent use.
type Client struct {
	opts      Options // timeouts filled with defaults
	conn      *net.UnixConn
	raw       syscall.RawConn
	readOOB   []byte // owned exclusively by readLoop
	proc      *process
	capsets   map[capsetKey][]byte // immutable after Start
	build     string               // immutable after Start
	mode      gpuproto.Mode        // immutable after Start
	writeSem  chan struct{}        // capacity 1; held while one frame is written
	failed    chan struct{}        // closed by lose after every pending call got its lost result
	done      chan struct{}        // closed by lose after failed
	wg        sync.WaitGroup       // reader, deadline loop, waiter, stderr pump, undo goroutines
	closeOnce sync.Once

	mu            sync.Mutex
	nextSeq       uint32             // guarded by mu
	pending       map[uint32]*call   // guarded by mu; nil after loss
	head, tail    *call              // guarded by mu; FIFO order of pending calls
	headSince     time.Time          // guarded by mu; when the previous head reply promoted c.head
	lost          error              // guarded by mu; set once
	sink          gpuproto.EventSink // guarded by mu
	lostDelivered bool               // guarded by mu: the reader finished with no sink, or called RendererLost
}

type capsetKey struct{ id, version uint32 }

// call is one request that waits for its reply.
type call struct {
	op               gpuproto.Op
	ctxID            uint32
	expectFD         bool                    // BLOB_CREATE with BlobFlagMappable, or RES_CREATE
	expectCapsetSize uint32                  // GET_CAPSET expected payload size
	blob             gpuproto.BlobCreate     // for BLOB_CREATE validation and undo
	res              gpuproto.ResourceCreate // for RES_CREATE validation and undo
	timeout          time.Duration
	seq              uint32      // guarded by Client.mu; assigned by register
	writtenAt        time.Time   // guarded by Client.mu; zero until frame write finishes
	deadline         time.Time   // guarded by Client.mu; non-zero only for the written FIFO head
	prev, next       *call       // guarded by Client.mu; intrusive FIFO queue links
	done             chan result // nil for fire-and-forget; else capacity 1
	abandoned        bool        // guarded by Client.mu; the caller left after cancellation
}

type result struct {
	hdr              gpuproto.Header
	payload          []byte
	shm              *fd.HostHandle // owned by the receiver of the result
	blobReply        gpuproto.BlobCreateReply
	resReply         gpuproto.ResCreateReply
	testConfineReply gpuproto.TestConfineReply
	err              error
}

// Start starts the renderer at opts.Path, completes the handshake (HELLO,
// then GET_CAPSET for every capset version), and returns a Client. It must
// run before the host lockdown. A failure returns a *StartError, and Start
// has then killed and reaped the process. ctx bounds the start together with
// opts.StartTimeout.
func Start(ctx context.Context, opts Options) (*Client, error) {
	opts = opts.withDefaults()
	if !opts.Mode.Valid() {
		return nil, &StartError{
			Path:     opts.Path,
			ExitCode: -1,
			Err:      fmt.Errorf("unknown renderer mode %d", opts.Mode),
		}
	}
	if !filepath.IsAbs(opts.Path) {
		return nil, &StartError{
			Path:     opts.Path,
			ExitCode: -1,
			Err:      errors.New("renderer path is not absolute"),
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, &StartError{
			Path:     opts.Path,
			ExitCode: -1,
			Err:      err,
		}
	}

	proc, conn, stderrR, err := startProcess(ctx, opts)
	if err != nil {
		return nil, &StartError{
			Path:     opts.Path,
			ExitCode: -1,
			Err:      err,
		}
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		proc.kill()
		_ = proc.wait()
		_ = conn.Close()
		_ = stderrR.Close()
		return nil, &StartError{
			Path:     opts.Path,
			ExitCode: -1,
			Err:      fmt.Errorf("syscallconn: %w", err),
		}
	}

	c := &Client{
		opts:     opts,
		conn:     conn,
		raw:      raw,
		readOOB:  make([]byte, unix.CmsgSpace(maxControlFDs*4)),
		proc:     proc,
		capsets:  make(map[capsetKey][]byte),
		writeSem: make(chan struct{}, 1),
		failed:   make(chan struct{}),
		done:     make(chan struct{}),
		nextSeq:  1,
		pending:  make(map[uint32]*call),
	}

	c.wg.Add(4)
	go c.readLoop()
	go c.deadlineLoop()
	go c.waitProcess()
	go func() {
		defer c.wg.Done()
		pumpStderr(stderrR, opts.Log, proc.tail)
	}()

	failStart := func(cause error) (*Client, error) {
		c.lose(cause, true)
		c.wg.Wait()
		return nil, &StartError{
			Path:     opts.Path,
			ExitCode: exitCode(c.proc),
			Stderr:   c.proc.tail.lines(),
			Err:      cause,
		}
	}

	hctx, cancel := context.WithTimeout(ctx, opts.StartTimeout)
	defer cancel()

	helloPayload := gpuproto.AppendPayload(nil, gpuproto.HelloRequest{
		Version: gpuproto.Version,
		Mode:    opts.Mode,
	})
	helloCall := &call{
		op:      gpuproto.OpHello,
		timeout: opts.StartTimeout,
		done:    make(chan result, 1),
	}
	res, err := c.roundTrip(hctx, helloCall, helloPayload, nil)
	if err != nil {
		return failStart(err)
	}
	info, err := gpuproto.DecodeHello(res.payload)
	if err != nil {
		return failStart(err)
	}
	if info.Version != gpuproto.Version {
		return failStart(fmt.Errorf("HELLO version %d, want %d", info.Version, gpuproto.Version))
	}
	if info.Mode != opts.Mode {
		return failStart(fmt.Errorf("HELLO mode %s, want %s", info.Mode, opts.Mode))
	}
	allowedCapsets := opts.Mode.Capsets()
	primaryCapset := opts.Mode.PrimaryCapset()
	seenCapsets := make(map[uint32]bool, len(info.Caps))
	for _, capInfo := range info.Caps {
		if !slices.Contains(allowedCapsets, capInfo.ID) || seenCapsets[capInfo.ID] {
			return failStart(fmt.Errorf("HELLO capset %d is not a capset of mode %s", capInfo.ID, opts.Mode))
		}
		seenCapsets[capInfo.ID] = true
	}
	if !seenCapsets[primaryCapset] {
		return failStart(fmt.Errorf("HELLO has no capset %d for mode %s", primaryCapset, opts.Mode))
	}
	c.build = info.Build

	for _, capInfo := range info.Caps {
		for version := uint32(0); version <= capInfo.MaxVersion; version++ {
			reqPayload := gpuproto.AppendPayload(nil, gpuproto.GetCapsetRequest{
				ID:      capInfo.ID,
				Version: version,
			})
			cl := &call{
				op:               gpuproto.OpGetCapset,
				expectCapsetSize: capInfo.MaxSize,
				timeout:          opts.StartTimeout,
				done:             make(chan result, 1),
			}
			capRes, err := c.roundTrip(hctx, cl, reqPayload, nil)
			if err != nil {
				return failStart(err)
			}
			if uint32(len(capRes.payload)) != capInfo.MaxSize {
				return failStart(fmt.Errorf("GET_CAPSET (%d, %d) length %d, want %d", capInfo.ID, version, len(capRes.payload), capInfo.MaxSize))
			}
			c.capsets[capsetKey{id: capInfo.ID, version: version}] = bytes.Clone(capRes.payload)
		}
	}
	c.mode = info.Mode

	return c, nil
}

func (c *Client) waitProcess() {
	defer c.wg.Done()
	c.proc.wait()
	close(c.proc.exited)
	c.lose(exitCause(c.proc.state), false)
}

// Mode returns the mode that the renderer confirmed in HELLO. It does no I/O.
func (c *Client) Mode() gpuproto.Mode {
	return c.mode
}

// Capset returns the capset data of id at version, as cached during the
// handshake. It does no I/O. ok is false for an unknown id or a version above
// the maximum.
func (c *Client) Capset(id, version uint32) ([]byte, bool) {
	data, ok := c.capsets[capsetKey{id: id, version: version}]
	if !ok {
		return nil, false
	}
	return bytes.Clone(data), true
}

// CreateContext creates ctxID with capsetID and waits for the reply. name is
// the guest debug name (at most 64 bytes; may be empty).
func (c *Client) CreateContext(ctx context.Context, ctxID, capsetID uint32, name string) error {
	if err := c.lostErr(); err != nil {
		return err
	}
	if ctxID == 0 {
		return &gpuproto.StatusError{Op: gpuproto.OpCtxCreate, Status: gpuproto.StatusInvalid}
	}
	payload, err := gpuproto.AppendCtxCreate(nil, capsetID, name)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gpurender: %s: %w", gpuproto.OpCtxCreate, err)
	}
	cl := &call{
		op:      gpuproto.OpCtxCreate,
		ctxID:   ctxID,
		timeout: c.opts.RequestTimeout,
		done:    make(chan result, 1),
	}
	_, err = c.roundTrip(ctx, cl, payload, nil)
	return err
}

// DestroyContext sends CTX_DESTROY and returns without waiting for the reply.
func (c *Client) DestroyContext(ctxID uint32) error {
	if err := c.lostErr(); err != nil {
		return err
	}
	if ctxID == 0 {
		return &gpuproto.StatusError{Op: gpuproto.OpCtxDestroy, Status: gpuproto.StatusInvalid}
	}
	cl := &call{
		op:      gpuproto.OpCtxDestroy,
		ctxID:   ctxID,
		timeout: c.opts.RequestTimeout,
	}
	return c.send(cl, nil, nil)
}

// CreateBlob creates and attaches a blob, then waits for the reply. On
// success the caller owns Blob.Shm.
func (c *Client) CreateBlob(ctx context.Context, req gpuproto.BlobCreate) (gpuproto.Blob, error) {
	if err := c.lostErr(); err != nil {
		return gpuproto.Blob{}, err
	}
	if err := req.Validate(); err != nil {
		return gpuproto.Blob{}, err
	}
	if err := ctx.Err(); err != nil {
		return gpuproto.Blob{}, fmt.Errorf("gpurender: %s: %w", gpuproto.OpBlobCreate, err)
	}
	payload := gpuproto.AppendPayload(nil, gpuproto.BlobCreateRequest{
		ResID:     req.ResID,
		BlobMem:   req.BlobMem,
		BlobFlags: req.BlobFlags,
		BlobID:    req.BlobID,
		Size:      req.Size,
	})
	cl := &call{
		op:       gpuproto.OpBlobCreate,
		ctxID:    req.CtxID,
		expectFD: req.BlobFlags&gpuproto.BlobFlagMappable != 0,
		blob:     req,
		timeout:  c.opts.RequestTimeout,
		done:     make(chan result, 1),
	}
	res, err := c.roundTrip(ctx, cl, payload, nil)
	if err != nil {
		return gpuproto.Blob{}, err
	}
	return gpuproto.Blob{
		Shm:      res.shm,
		HostSize: res.blobReply.HostSize,
	}, nil
}

// CreateResource creates a virgl resource with a shared-memory backing,
// attaches it to req.CtxID, and waits for the reply. On success the caller
// owns Blob.Shm (never nil) and Blob.HostSize is the backing size.
func (c *Client) CreateResource(ctx context.Context, req gpuproto.ResourceCreate) (gpuproto.Blob, error) {
	if err := c.lostErr(); err != nil {
		return gpuproto.Blob{}, err
	}
	if err := req.Validate(); err != nil {
		return gpuproto.Blob{}, err
	}
	if err := ctx.Err(); err != nil {
		return gpuproto.Blob{}, fmt.Errorf("gpurender: %s: %w", gpuproto.OpResCreate, err)
	}
	payload := gpuproto.AppendPayload(nil, req.Request())
	cl := &call{
		op:       gpuproto.OpResCreate,
		ctxID:    req.CtxID,
		expectFD: true,
		res:      req,
		timeout:  c.opts.RequestTimeout,
		done:     make(chan result, 1),
	}
	res, err := c.roundTrip(ctx, cl, payload, nil)
	if err != nil {
		return gpuproto.Blob{}, err
	}
	return gpuproto.Blob{
		Shm:      res.shm,
		HostSize: res.resReply.HostSize,
	}, nil
}

// Transfer copies between the backing and the host resource and waits for
// the reply. The copy is complete when Transfer returns nil.
func (c *Client) Transfer(ctx context.Context, req gpuproto.Transfer) error {
	if err := c.lostErr(); err != nil {
		return err
	}
	if err := req.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("gpurender: %s: %w", gpuproto.OpTransfer, err)
	}
	payload := gpuproto.AppendPayload(nil, req.Request())
	cl := &call{
		op:      gpuproto.OpTransfer,
		ctxID:   req.CtxID,
		timeout: c.opts.SubmitTimeout,
		done:    make(chan result, 1),
	}
	_, err := c.roundTrip(ctx, cl, payload, nil)
	return err
}

// UnrefResource sends RES_UNREF (detach, then unref) and returns without
// waiting for the reply.
func (c *Client) UnrefResource(ctxID, resID uint32) error {
	if err := c.lostErr(); err != nil {
		return err
	}
	if ctxID == 0 || resID == 0 {
		return &gpuproto.StatusError{Op: gpuproto.OpResUnref, Status: gpuproto.StatusInvalid}
	}
	payload := gpuproto.AppendPayload(nil, gpuproto.ResUnrefRequest{ResID: resID})
	cl := &call{
		op:      gpuproto.OpResUnref,
		ctxID:   ctxID,
		timeout: c.opts.RequestTimeout,
	}
	return c.send(cl, payload, nil)
}

// Submit sends cmd with an optional fence and returns once the request is
// written. It does not wait for the reply. A write that blocks past the submit
// timeout loses the renderer.
func (c *Client) Submit(ctxID uint32, cmd []byte, fence *gpuproto.Fence) error {
	if err := c.lostErr(); err != nil {
		return err
	}
	if ctxID == 0 {
		return &gpuproto.StatusError{Op: gpuproto.OpSubmit, Status: gpuproto.StatusInvalid}
	}
	if len(cmd)%4 != 0 || len(cmd) > gpuproto.MaxSubmitBytes {
		return &gpuproto.StatusError{Op: gpuproto.OpSubmit, Status: gpuproto.StatusInvalid}
	}
	req := gpuproto.SubmitRequest{
		CmdLen: uint32(len(cmd)),
	}
	if fence != nil {
		if err := fence.Validate(); err != nil {
			return err
		}
		req.Flags = gpuproto.SubmitFlagFence
		req.RingIdx = fence.RingIdx
		req.FenceID = fence.ID
	}
	prefix := gpuproto.AppendPayload(nil, req)
	cl := &call{
		op:      gpuproto.OpSubmit,
		ctxID:   ctxID,
		timeout: c.opts.SubmitTimeout,
	}
	return c.send(cl, prefix, cmd)
}

// TestConfinement asks the renderer to run its confinement checks. The
// renderer runs them only when it started with Options.TestOps; otherwise the
// call returns a *gpuproto.StatusError with StatusNotSupported. Tests only.
func (c *Client) TestConfinement(ctx context.Context) (gpuproto.TestConfineReply, error) {
	if err := c.lostErr(); err != nil {
		return gpuproto.TestConfineReply{}, err
	}
	if err := ctx.Err(); err != nil {
		return gpuproto.TestConfineReply{}, fmt.Errorf("gpurender: %s: %w", gpuproto.OpTestConfine, err)
	}
	cl := &call{
		op:      gpuproto.OpTestConfine,
		timeout: c.opts.RequestTimeout,
		done:    make(chan result, 1),
	}
	res, err := c.roundTrip(ctx, cl, nil, nil)
	if err != nil {
		return gpuproto.TestConfineReply{}, err
	}
	return res.testConfineReply, nil
}

// SetEventSink installs the event receiver. Call it once, before the first
// CreateContext. A nil sink or a second call panics.
func (c *Client) SetEventSink(sink gpuproto.EventSink) {
	if sink == nil {
		panic("gpurender: nil EventSink")
	}
	c.mu.Lock()
	if c.sink != nil {
		c.mu.Unlock()
		panic("gpurender: SetEventSink called more than once")
	}
	c.sink = sink
	deliverNow := c.lostDelivered
	lostErr := c.lost
	c.mu.Unlock()
	if deliverNow {
		sink.RendererLost(lostErr)
	}
}

// Close ends the renderer: it marks the client lost, closes the socket so the
// renderer reads end of file, waits up to KillGrace for the exit, sends
// SIGKILL after that, reaps the process, and waits for every goroutine of the
// client. It returns nil. Later calls return an error that wraps
// gpuproto.ErrRendererLost. Close is safe to call more than once.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.lose(errClosed, false)
		timer := time.NewTimer(KillGrace)
		select {
		case <-c.proc.exited:
			timer.Stop()
		case <-timer.C:
			c.proc.kill()
		}
		c.wg.Wait()
	})
	return nil
}

// PID returns the process ID of the renderer.
func (c *Client) PID() int {
	return c.proc.pid
}

// Build returns the build string of the HELLO reply.
func (c *Client) Build() string {
	return c.build
}

func (c *Client) lostErr() error {
	c.mu.Lock()
	err := c.lost
	c.mu.Unlock()
	return err
}

func (c *Client) register(cl *call) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lost != nil {
		return 0, c.lost
	}
	var seq uint32
	for {
		seq = c.nextSeq
		c.nextSeq++
		if seq == 0 {
			continue
		}
		if _, exists := c.pending[seq]; !exists {
			break
		}
	}
	cl.seq = seq
	cl.writtenAt = time.Time{}
	cl.deadline = time.Time{}
	c.pending[seq] = cl
	c.enqueueLocked(cl)
	return seq, nil
}

// enqueueLocked appends cl to the FIFO queue while the caller holds c.mu.
func (c *Client) enqueueLocked(cl *call) {
	cl.prev = c.tail
	cl.next = nil
	if c.tail != nil {
		c.tail.next = cl
	} else {
		c.head = cl
		c.headSince = time.Time{}
	}
	c.tail = cl
}

// dequeueLocked unlinks cl from the FIFO queue while the caller holds c.mu.
func (c *Client) dequeueLocked(cl *call) {
	if cl.prev != nil {
		cl.prev.next = cl.next
	} else if c.head == cl {
		c.head = cl.next
	}
	if cl.next != nil {
		cl.next.prev = cl.prev
	} else if c.tail == cl {
		c.tail = cl.prev
	}
	cl.prev = nil
	cl.next = nil
}

// armHeadDeadlineLocked sets the FIFO head deadline from max(writtenAt, headSince).
// Callers hold c.mu with cl equal to c.head and a non-zero writtenAt.
func (c *Client) armHeadDeadlineLocked(cl *call) {
	start := cl.writtenAt
	if c.headSince.After(start) {
		start = c.headSince
	}
	cl.deadline = start.Add(cl.timeout)
}

// advanceHeadLocked promotes the next FIFO entry after a head reply arrives at now.
// The caller holds c.mu.
func (c *Client) advanceHeadLocked(now time.Time) {
	if c.head == nil {
		c.headSince = time.Time{}
		return
	}
	c.headSince = now
	if !c.head.writtenAt.IsZero() {
		c.armHeadDeadlineLocked(c.head)
	}
}

// markWritten records the frame write completion time and arms the deadline
// when cl is the FIFO head. Callers hold writeSem across register,
// writeFrameLocked, and markWritten so the queue matches wire order.
func (c *Client) markWritten(cl *call) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lost != nil || c.pending[cl.seq] != cl {
		return
	}
	cl.writtenAt = time.Now()
	if c.head == cl {
		c.armHeadDeadlineLocked(cl)
	}
}

func buildFrame(op gpuproto.Op, seq, ctxID uint32, fixedPayload, tail []byte) net.Buffers {
	hdr := gpuproto.Header{
		Magic:      gpuproto.Magic,
		Op:         op,
		Seq:        seq,
		CtxID:      ctxID,
		PayloadLen: uint32(len(fixedPayload) + len(tail)),
	}
	head := make([]byte, 0, gpuproto.HeaderSize+len(fixedPayload))
	head = gpuproto.AppendHeader(head, hdr)
	head = append(head, fixedPayload...)
	if len(tail) > 0 {
		return net.Buffers{head, tail}
	}
	return net.Buffers{head}
}

// roundTrip acquires writeSem, registers a call, writes its frame, records the
// write completion time, and waits for its reply or for ctx. Holding writeSem
// across register, write, and markWritten keeps c.head..c.tail in wire order.
func (c *Client) roundTrip(ctx context.Context, cl *call, fixedPayload, tail []byte) (result, error) {
	if err := c.acquireWriteSem(ctx); err != nil {
		if ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return result{}, fmt.Errorf("gpurender: %s: %w", cl.op, ctx.Err())
		}
		return result{}, err
	}
	seq, err := c.register(cl)
	if err != nil {
		<-c.writeSem
		return result{}, err
	}
	frame := buildFrame(cl.op, seq, cl.ctxID, fixedPayload, tail)
	err = c.writeFrameLocked(cl.op, frame, cl.timeout)
	if err == nil {
		c.markWritten(cl)
	}
	<-c.writeSem
	if err != nil {
		return result{}, err
	}

	select {
	case r := <-cl.done:
		return r, r.err
	case <-ctx.Done():
		c.mu.Lock()
		if _, ok := c.pending[seq]; ok {
			cl.abandoned = true
			c.mu.Unlock()
			return result{}, fmt.Errorf("gpurender: %s: %w", cl.op, ctx.Err())
		}
		c.mu.Unlock()
		r := <-cl.done
		return r, r.err
	}
}

// send acquires writeSem, registers a fire-and-forget call, writes its frame,
// and records its write completion time before releasing writeSem.
func (c *Client) send(cl *call, fixedPayload, tail []byte) error {
	if err := c.acquireWriteSem(nil); err != nil {
		return err
	}
	defer func() { <-c.writeSem }()
	seq, err := c.register(cl)
	if err != nil {
		return err
	}
	frame := buildFrame(cl.op, seq, cl.ctxID, fixedPayload, tail)
	err = c.writeFrameLocked(cl.op, frame, cl.timeout)
	if err == nil {
		c.markWritten(cl)
	}
	return err
}

// lose marks the client lost with cause, closes the socket, fails every
// pending call, and kills the process when kill is true. Only the first call
// has an effect. It never calls the sink.
func (c *Client) lose(cause error, kill bool) {
	c.mu.Lock()
	if c.lost != nil {
		c.mu.Unlock()
		return
	}
	lostErr := fmt.Errorf("%w: %w", gpuproto.ErrRendererLost, cause)
	c.lost = lostErr
	pend := c.pending
	c.pending = nil
	c.head = nil
	c.tail = nil
	c.headSince = time.Time{}
	c.mu.Unlock()

	// Deliver lost results to all pending callers before closing c.failed so
	// readLoop never invokes RendererLost while a caller is still waiting.
	for _, cl := range pend {
		if cl.done != nil && !cl.abandoned {
			cl.done <- result{err: lostErr}
		}
	}
	close(c.failed)
	close(c.done)
	if kill {
		c.proc.kill()
	}
	_ = c.conn.Close()
}

// deadlineLoop inspects the FIFO head every deadlineTick and loses the
// renderer when that head exceeds its budget. Queued calls behind the head do
// not expire until earlier replies arrive. It exits when c.done closes.
func (c *Client) deadlineLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(deadlineTick)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-ticker.C:
			var (
				expired bool
				expSeq  uint32
				expOp   gpuproto.Op
				expTO   time.Duration
			)
			c.mu.Lock()
			if cl := c.head; cl != nil && !cl.deadline.IsZero() && now.After(cl.deadline) {
				expired = true
				expSeq = cl.seq
				expOp = cl.op
				expTO = cl.timeout
			}
			c.mu.Unlock()
			if expired {
				c.lose(fmt.Errorf("%w: no reply to %s seq %d within %s", ErrRendererHung, expOp, expSeq, expTO), true)
				return
			}
		}
	}
}

// undo runs cleanup for an abandoned request on a new goroutine because the
// reader goroutine must never write to the socket (a writer holding writeSem
// can wait for the reader to drain replies).
func (c *Client) undo(fn func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		fn()
	}()
}

// readLoop reads frames until an error, dispatches replies and events, and
// delivers RendererLost once when it ends.
func (c *Client) readLoop() {
	defer c.wg.Done()
	var hdrBuf [gpuproto.HeaderSize]byte

	for {
		deadlineArmed := false
		shm, err := c.readHeader(&hdrBuf, &deadlineArmed)
		if err != nil {
			cause := err
			kill := true
			if isPeerCloseErr(err) {
				fallback := err
				if errors.Is(err, io.EOF) {
					fallback = errors.New("renderer closed the connection")
				}
				cause, kill = c.peerExitCause(fallback)
			}
			c.lose(cause, kill)
			break
		}

		hdr, err := gpuproto.ParseHeader(hdrBuf[:], gpuproto.FromRenderer)
		if err != nil {
			closeHandle(shm)
			c.lose(fmt.Errorf("protocol error: %w", err), true)
			break
		}

		hasFD := shm != nil
		wantFD := hdr.Flags&gpuproto.FlagFD != 0
		if hasFD != wantFD {
			closeHandle(shm)
			c.lose(fmt.Errorf("protocol error: %s FlagFD=%v with descriptor present=%v", hdr.Op, wantFD, hasFD), true)
			break
		}

		var payload []byte
		if hdr.PayloadLen > 0 {
			payload = make([]byte, hdr.PayloadLen)
			if err := c.readPayload(payload, &deadlineArmed); err != nil {
				closeHandle(shm)
				fallback := fmt.Errorf("read %s payload: %w", hdr.Op, err)
				cause, kill := fallback, true
				if isPeerCloseErr(err) {
					cause, kill = c.peerExitCause(fallback)
				}
				c.lose(cause, kill)
				break
			}
		}

		if deadlineArmed {
			if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
				closeHandle(shm)
				c.lose(fmt.Errorf("clear read deadline: %w", err), true)
				break
			}
		}

		if hdr.Flags&gpuproto.FlagEvent != 0 {
			if !c.dispatchEvent(hdr, payload) {
				break
			}
			continue
		}

		if !c.dispatchReply(hdr, payload, shm) {
			break
		}
	}

	<-c.failed
	c.mu.Lock()
	sink := c.sink
	lostErr := c.lost
	c.lostDelivered = true
	c.mu.Unlock()
	if sink != nil {
		sink.RendererLost(lostErr)
	}
}

func isPeerCloseErr(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}

// peerExitCause waits briefly for the renderer process to exit when a socket
// peer-close error races with a self-exit such as the memory watchdog, so the
// recorded loss cause preserves *ExitError.
func (c *Client) peerExitCause(fallback error) (cause error, kill bool) {
	if c.proc == nil || c.lostErr() != nil {
		return fallback, true
	}
	timer := time.NewTimer(KillGrace)
	defer timer.Stop()
	select {
	case <-c.proc.exited:
		return exitCause(c.proc.state), false
	case <-c.done:
		return fallback, false
	case <-timer.C:
		return fallback, true
	}
}

func (c *Client) dispatchEvent(hdr gpuproto.Header, payload []byte) bool {
	c.mu.Lock()
	lost := c.lost != nil
	sink := c.sink
	c.mu.Unlock()
	if lost {
		return false
	}

	switch hdr.Op {
	case gpuproto.OpFenceDone:
		ev, err := gpuproto.DecodePayload[gpuproto.FenceDoneEvent](payload)
		if err != nil {
			c.lose(fmt.Errorf("protocol error: %w", err), true)
			return false
		}
		if sink != nil {
			sink.FenceDone(hdr.CtxID, ev.RingIdx, ev.FenceID)
		}
	case gpuproto.OpCtxLost:
		ev, err := gpuproto.DecodePayload[gpuproto.CtxLostEvent](payload)
		if err != nil {
			c.lose(fmt.Errorf("protocol error: %w", err), true)
			return false
		}
		if ev.Reason != gpuproto.CtxLostSubmitFailed && ev.Reason != gpuproto.CtxLostFenceFailed {
			c.lose(fmt.Errorf("protocol error: CTX_LOST unknown reason %d", ev.Reason), true)
			return false
		}
		if sink != nil {
			sink.ContextLost(hdr.CtxID)
		}
	default:
		c.lose(fmt.Errorf("protocol error: unknown event op %s", hdr.Op), true)
		return false
	}
	return true
}

func (c *Client) dispatchReply(hdr gpuproto.Header, payload []byte, shm *fd.HostHandle) bool {
	c.mu.Lock()
	if c.lost != nil {
		c.mu.Unlock()
		closeHandle(shm)
		return false
	}
	cl, ok := c.pending[hdr.Seq]
	c.mu.Unlock()

	if !ok {
		closeHandle(shm)
		c.lose(fmt.Errorf("protocol error: unexpected reply seq %d for %s", hdr.Seq, hdr.Op), true)
		return false
	}

	validated, err := validateReply(cl, hdr, payload)
	if err != nil {
		closeHandle(shm)
		c.lose(fmt.Errorf("protocol error: %w", err), true)
		return false
	}

	c.mu.Lock()
	if c.lost != nil {
		c.mu.Unlock()
		closeHandle(shm)
		return false
	}
	cur, ok := c.pending[hdr.Seq]
	if !ok || cur != cl {
		c.mu.Unlock()
		closeHandle(shm)
		c.lose(fmt.Errorf("protocol error: unexpected reply seq %d for %s", hdr.Seq, hdr.Op), true)
		return false
	}
	delete(c.pending, hdr.Seq)
	wasHead := c.head == cl
	c.dequeueLocked(cl)
	if wasHead {
		c.advanceHeadLocked(time.Now())
	}
	abandoned := cl.abandoned
	sink := c.sink
	c.mu.Unlock()

	if cl.done == nil {
		closeHandle(shm)
		if hdr.Status != gpuproto.StatusOK {
			if hdr.Op == gpuproto.OpSubmit {
				if sink != nil {
					sink.ContextLost(hdr.CtxID)
				}
			} else if c.opts.Log != nil {
				c.opts.Log(fmt.Sprintf("gpurender: %s ctx %d refused: %s", hdr.Op, hdr.CtxID, hdr.Status))
			}
		}
		return true
	}

	if abandoned {
		closeHandle(shm)
		if hdr.Status == gpuproto.StatusOK {
			switch cl.op {
			case gpuproto.OpCtxCreate:
				ctxID := cl.ctxID
				c.undo(func() { _ = c.DestroyContext(ctxID) })
			case gpuproto.OpBlobCreate:
				ctxID, resID := cl.ctxID, cl.blob.ResID
				c.undo(func() { _ = c.UnrefResource(ctxID, resID) })
			case gpuproto.OpResCreate:
				ctxID, resID := cl.ctxID, cl.res.ResID
				c.undo(func() { _ = c.UnrefResource(ctxID, resID) })
			}
		}
		return true
	}

	if hdr.Status != gpuproto.StatusOK {
		closeHandle(shm)
		cl.done <- result{
			hdr: hdr,
			err: &gpuproto.StatusError{Op: hdr.Op, Status: hdr.Status},
		}
		return true
	}

	cl.done <- result{
		hdr:              hdr,
		payload:          payload,
		shm:              shm,
		blobReply:        validated.blobReply,
		resReply:         validated.resReply,
		testConfineReply: validated.testConfineReply,
	}
	return true
}

type validatedReply struct {
	blobReply        gpuproto.BlobCreateReply
	resReply         gpuproto.ResCreateReply
	testConfineReply gpuproto.TestConfineReply
}

func validateReply(cl *call, hdr gpuproto.Header, payload []byte) (validatedReply, error) {
	if hdr.Op != cl.op || hdr.CtxID != cl.ctxID {
		return validatedReply{}, fmt.Errorf("reply (%s, ctx %d) does not match call (%s, ctx %d)", hdr.Op, hdr.CtxID, cl.op, cl.ctxID)
	}
	wantFD := cl.expectFD && hdr.Status == gpuproto.StatusOK
	if (hdr.Flags&gpuproto.FlagFD != 0) != wantFD {
		return validatedReply{}, fmt.Errorf("%s reply FlagFD=%v, want %v", hdr.Op, hdr.Flags&gpuproto.FlagFD != 0, wantFD)
	}
	if hdr.Status != gpuproto.StatusOK {
		return validatedReply{}, nil
	}

	switch hdr.Op {
	case gpuproto.OpHello:
		info, err := gpuproto.DecodeHello(payload)
		if err != nil {
			return validatedReply{}, err
		}
		if info.Version != gpuproto.Version {
			return validatedReply{}, fmt.Errorf("HELLO version %d, want %d", info.Version, gpuproto.Version)
		}
		return validatedReply{}, nil
	case gpuproto.OpGetCapset:
		if uint32(len(payload)) != cl.expectCapsetSize {
			return validatedReply{}, fmt.Errorf("GET_CAPSET payload length %d, want %d", len(payload), cl.expectCapsetSize)
		}
		return validatedReply{}, nil
	case gpuproto.OpCtxCreate, gpuproto.OpCtxDestroy, gpuproto.OpResUnref, gpuproto.OpSubmit, gpuproto.OpTransfer:
		if len(payload) != 0 {
			return validatedReply{}, fmt.Errorf("%s reply payload length %d, want 0", hdr.Op, len(payload))
		}
		return validatedReply{}, nil
	case gpuproto.OpBlobCreate:
		rep, err := gpuproto.DecodePayload[gpuproto.BlobCreateReply](payload)
		if err != nil {
			return validatedReply{}, err
		}
		if cl.expectFD {
			if rep.FDType != gpuproto.FDTypeShm {
				return validatedReply{}, fmt.Errorf("BLOB_CREATE fd_type %d, want %d", rep.FDType, gpuproto.FDTypeShm)
			}
			if rep.HostSize < cl.blob.Size {
				return validatedReply{}, fmt.Errorf("BLOB_CREATE host_size %d below requested %d", rep.HostSize, cl.blob.Size)
			}
			if rep.HostSize%gpuproto.HostBlobAlign != 0 {
				return validatedReply{}, fmt.Errorf("BLOB_CREATE host_size %d is not aligned to %d", rep.HostSize, gpuproto.HostBlobAlign)
			}
			if rep.HostSize > gpuproto.MaxBlobBytes {
				return validatedReply{}, fmt.Errorf("BLOB_CREATE host_size %d exceeds max %d", rep.HostSize, gpuproto.MaxBlobBytes)
			}
		} else {
			if rep.HostSize != 0 || rep.FDType != 0 || rep.MapInfo != 0 {
				return validatedReply{}, fmt.Errorf("non-mappable BLOB_CREATE reply has host_size=%d fd_type=%d map_info=%d", rep.HostSize, rep.FDType, rep.MapInfo)
			}
		}
		return validatedReply{blobReply: rep}, nil
	case gpuproto.OpResCreate:
		rep, err := gpuproto.DecodePayload[gpuproto.ResCreateReply](payload)
		if err != nil {
			return validatedReply{}, err
		}
		if rep.FDType != gpuproto.FDTypeShm {
			return validatedReply{}, fmt.Errorf("RES_CREATE fd_type %d, want %d", rep.FDType, gpuproto.FDTypeShm)
		}
		if rep.Reserved != 0 {
			return validatedReply{}, fmt.Errorf("RES_CREATE reserved %#x, want 0", rep.Reserved)
		}
		if rep.HostSize < cl.res.Size {
			return validatedReply{}, fmt.Errorf("RES_CREATE host_size %d below requested %d", rep.HostSize, cl.res.Size)
		}
		if rep.HostSize%gpuproto.HostBlobAlign != 0 {
			return validatedReply{}, fmt.Errorf("RES_CREATE host_size %d is not aligned to %d", rep.HostSize, gpuproto.HostBlobAlign)
		}
		if rep.HostSize > gpuproto.MaxBlobBytes {
			return validatedReply{}, fmt.Errorf("RES_CREATE host_size %d exceeds max %d", rep.HostSize, gpuproto.MaxBlobBytes)
		}
		return validatedReply{resReply: rep}, nil
	case gpuproto.OpTestConfine:
		rep, err := gpuproto.DecodePayload[gpuproto.TestConfineReply](payload)
		if err != nil {
			return validatedReply{}, err
		}
		if rep.Checks != gpuproto.ConfineChecks {
			return validatedReply{}, fmt.Errorf("TEST_CONFINE checks %d, want %d", rep.Checks, gpuproto.ConfineChecks)
		}
		for i := range gpuproto.ConfineChecks {
			switch gpuproto.ConfineResult(rep.Results[i]) {
			case gpuproto.ConfineDenied, gpuproto.ConfineAllowed, gpuproto.ConfineUnexpected:
			default:
				return validatedReply{}, fmt.Errorf("TEST_CONFINE result[%d] = %d is invalid", i, rep.Results[i])
			}
		}
		for i := gpuproto.ConfineChecks; i < len(rep.Results); i++ {
			if rep.Results[i] != uint8(gpuproto.ConfineNotRun) {
				return validatedReply{}, fmt.Errorf("TEST_CONFINE unused result[%d] = %d, want 0", i, rep.Results[i])
			}
		}
		return validatedReply{testConfineReply: rep}, nil
	default:
		return validatedReply{}, fmt.Errorf("unexpected reply op %s", hdr.Op)
	}
}

func closeHandle(h *fd.HostHandle) {
	if h != nil {
		_ = h.Close()
	}
}
