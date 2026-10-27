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

//go:build darwin && arm64

package systrap

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:generate ./stub/build.sh ./stub

// stubImage is the ad-hoc signed Mach-O of the template process. The stub
// directory holds its sources and build.sh. A test rebuilds the image with
// clang and compares the bytes.
//
//go:embed stub/gvx-stub-darwin-arm64
var stubImage []byte

const (
	helloMsgID        = 77
	helloTimeout      = 20 * time.Second
	forkTimeout       = 20 * time.Second
	deathTimeout      = 10 * time.Second
	monitorPollMillis = 100
)

// machHeader mirrors mach_msg_header_t.
type machHeader struct {
	Bits    uint32
	Size    uint32
	Remote  uint32
	Local   uint32
	Voucher uint32
	ID      int32
}

// helloMsg is the message that the stub sends to announce itself. The kernel
// appends a trailer, so the buffer has room for one.
type helloMsg struct {
	Header machHeader
	Body   uint32
	Port   struct {
		Name uint32
		_    uint32
		Meta uint32
	}
	Hello   helloPayload
	Trailer [128]byte
}

// deadNameMsg mirrors mach_dead_name_notification_t.
type deadNameMsg struct {
	Header  machHeader
	NDR     [8]byte
	Port    uint32
	_       uint32
	Trailer [128]byte
}

// stubProc is one stub task. The template process and every forked child are
// stubProcs.
type stubProc struct {
	task machPort
	// pid is the host process ID of the stub task.
	pid int
	// deadCh closes when the kernel reports the task as dead.
	deadCh chan struct{}
	// dead is set when the kernel reports that the task is gone.
	dead atomic.Bool
	// onDead wakes every waiter of the task. It is set before the task runs guest code.
	onDead atomic.Pointer[func()]
}

func (p *stubProc) markDead() {
	if p.dead.Swap(true) {
		return
	}
	close(p.deadCh)
	if f := p.onDead.Load(); f != nil {
		(*f)()
	}
}

// stubHost owns the template process and forks stub tasks from it.
type stubHost struct {
	pool *pagePool
	self machPort

	// recv is the receive right on which the stub tasks announce themselves
	// and on which the kernel delivers dead-name notifications.
	recv machPort
	pid  int
	tmpl *stubProc

	hello helloPayload
	ctl   *ctlPage
	// ctlAddr is the address of ctl in the Sentry.
	ctlAddr uint64

	mu sync.Mutex
	// ctlMu serializes commands on the control page.
	ctlMu   sync.Mutex
	cookie  uint64
	waiters map[uint64]chan helloMsg
	procs   map[machPort]*stubProc

	stop          chan struct{}
	fillStop      chan struct{}
	ready         chan *stubProc
	startFillOnce sync.Once
	fillWG        sync.WaitGroup
	monitor       sync.WaitGroup
	closed        bool
	closeErr      error
}

const darwinStubPoolDepth = 2

// spawnStubHost starts the template process. It must run before the Sentry
// locks itself down, because the lockdown profile forbids process creation.
func spawnStubHost(pool *pagePool) (*stubHost, error) {
	h := &stubHost{
		pool:     pool,
		self:     selfTask(),
		waiters:  make(map[uint64]chan helloMsg),
		procs:    make(map[machPort]*stubProc),
		stop:     make(chan struct{}),
		fillStop: make(chan struct{}),
		ready:    make(chan *stubProc, darwinStubPoolDepth),
	}
	recv, err := portAllocateReceive(h.self)
	if err != nil {
		return nil, err
	}
	h.recv = recv
	if err := portInsertSendRight(h.self, recv); err != nil {
		_ = portDestroy(h.self, recv)
		return nil, err
	}
	dir, err := os.MkdirTemp("", "gvx-stub-")
	if err != nil {
		_ = portDestroy(h.self, recv)
		return nil, fmt.Errorf("create stub directory: %w", err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "gvx-stub")
	if err := os.WriteFile(path, stubImage, 0o700); err != nil {
		_ = portDestroy(h.self, recv)
		return nil, fmt.Errorf("write the stub image: %w", err)
	}
	pid, err := posixSpawnStub(path, recv)
	if err != nil {
		_ = portDestroy(h.self, recv)
		return nil, err
	}
	h.pid = pid
	var msg helloMsg
	if err := h.receive(&msg, helloTimeout); err != nil {
		h.killPid()
		_ = portDestroy(h.self, recv)
		return nil, fmt.Errorf("wait for the stub hello (stub pid %d): %w", pid, err)
	}
	if err := checkHello(&msg, 0); err != nil {
		h.killPid()
		_ = portDestroy(h.self, recv)
		return nil, err
	}
	h.hello = msg.Hello
	h.tmpl = &stubProc{task: machPort(msg.Port.Name), pid: int(msg.Hello.PID), deadCh: make(chan struct{})}
	local, err := vmRemapFrom(h.tmpl.task, h.hello.CtlAddr, blockSize)
	if err != nil {
		h.killPid()
		_ = portDestroy(h.self, recv)
		return nil, fmt.Errorf("map the stub control page: %w", err)
	}
	h.ctlAddr = local
	h.ctl = (*ctlPage)(addrPtr(local))
	h.procs[h.tmpl.task] = h.tmpl
	if err := portRequestDeadName(h.self, h.tmpl.task, recv); err != nil {
		h.close()
		return nil, err
	}
	h.monitor.Add(1)
	go h.monitorLoop()
	return h, nil
}

// posixSpawnStub runs the stub image. The only kernel object that the child
// starts with is a resource-exception registration that names the Sentry's
// port. It has no file descriptor, no environment and the default signal state.
func posixSpawnStub(path string, port machPort) (int, error) {
	var attr uintptr
	if err := kr("posix_spawnattr_init", machCalls.spawnattrInit.call(uintptr(unsafe.Pointer(&attr)))); err != nil {
		return 0, err
	}
	defer machCalls.spawnattrDestroy.call(uintptr(unsafe.Pointer(&attr)))
	// The template leads a new process group. It signals the group when the
	// Sentry dies, so no stub task outlives the Sentry.
	flags := uintptr(posixSpawnCloexecDefault | posixSpawnSetSigDef | posixSpawnSetSigMask | posixSpawnSetPgroup)
	if r := machCalls.spawnattrSetPgroup.call(uintptr(unsafe.Pointer(&attr)), 0); int32(r) != 0 {
		return 0, fmt.Errorf("posix_spawnattr_setpgroup: %w", syscall.Errno(r))
	}
	if r := machCalls.spawnattrSetFlags.call(uintptr(unsafe.Pointer(&attr)), flags); int32(r) != 0 {
		return 0, fmt.Errorf("posix_spawnattr_setflags: %w", syscall.Errno(r))
	}
	var all, none uint32 = ^uint32(0), 0
	if r := machCalls.spawnattrSetSigDefault.call(uintptr(unsafe.Pointer(&attr)), uintptr(unsafe.Pointer(&all))); int32(r) != 0 {
		return 0, fmt.Errorf("posix_spawnattr_setsigdefault: %w", syscall.Errno(r))
	}
	if r := machCalls.spawnattrSetSigMask.call(uintptr(unsafe.Pointer(&attr)), uintptr(unsafe.Pointer(&none))); int32(r) != 0 {
		return 0, fmt.Errorf("posix_spawnattr_setsigmask: %w", syscall.Errno(r))
	}
	if r := machCalls.spawnattrSetExceptionPorts.call(uintptr(unsafe.Pointer(&attr)), excMaskResource, uintptr(port), exceptionDefault, 0); int32(r) != 0 {
		return 0, fmt.Errorf("posix_spawnattr_setexceptionports_np: %w", syscall.Errno(r))
	}
	cpath := append([]byte(path), 0)
	argv := [2]uintptr{uintptr(unsafe.Pointer(&cpath[0])), 0}
	envp := [1]uintptr{0}
	var pid int32
	r := machCalls.spawn.call(uintptr(unsafe.Pointer(&pid)), uintptr(unsafe.Pointer(&cpath[0])), 0,
		uintptr(unsafe.Pointer(&attr)), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])))
	runtime.KeepAlive(cpath)
	runtime.KeepAlive(&argv)
	runtime.KeepAlive(&envp)
	runtime.KeepAlive(&attr)
	if int32(r) != 0 {
		return 0, fmt.Errorf("posix_spawn %s: %w", path, syscall.Errno(r))
	}
	return int(pid), nil
}

// checkHello validates a hello message from the stub.
func checkHello(m *helloMsg, wantKind uint32) error {
	if m.Header.ID != helloMsgID || m.Hello.Magic != helloMagic {
		return fmt.Errorf("unexpected message id %d from the stub", m.Header.ID)
	}
	if m.Hello.Version != protocolVersion {
		return fmt.Errorf("stub protocol version %d, want %d", m.Hello.Version, protocolVersion)
	}
	if m.Hello.Kind != wantKind {
		return fmt.Errorf("stub hello kind %d, want %d", m.Hello.Kind, wantKind)
	}
	if m.Hello.PageSize != uint64(unix.Getpagesize()) {
		return fmt.Errorf("stub page size %d differs from the Sentry page size %d", m.Hello.PageSize, unix.Getpagesize())
	}
	if want := expectedLayout(); m.Hello.Layout != want {
		return fmt.Errorf("stub layout %v differs from the Sentry layout %v", m.Hello.Layout, want)
	}
	if machPort(m.Port.Name) == machPortNull {
		return errors.New("stub hello carries no task port")
	}
	return nil
}

// receive waits for one message on the Sentry's port.
func (h *stubHost) receive(msg *helloMsg, timeout time.Duration) error {
	*msg = helloMsg{}
	ms := uint32(timeout / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	if k := machMsgCall(unsafe.Pointer(msg), machRcvMsg|machRcvTimeout, 0, uint32(unsafe.Sizeof(*msg)), h.recv, ms); k != kernSuccess {
		return &MachError{Op: "mach_msg receive", Code: k}
	}
	return nil
}

// monitorLoop delivers hello messages from forked children and dead-name
// notifications for stub tasks.
func (h *stubHost) monitorLoop() {
	defer h.monitor.Done()
	var msg helloMsg
	for {
		select {
		case <-h.stop:
			return
		default:
		}
		msg = helloMsg{}
		k := machMsgCall(unsafe.Pointer(&msg), machRcvMsg|machRcvTimeout, 0, uint32(unsafe.Sizeof(msg)), h.recv, monitorPollMillis)
		switch k {
		case kernSuccess:
		case machRcvTimedOut, machRcvInterrupted:
			continue
		default:
			// The port is gone. Close destroys it and stops the loop.
			return
		}
		switch msg.Header.ID {
		case helloMsgID:
			h.deliverHello(msg)
		case machNotifyDeadName:
			dn := (*deadNameMsg)(unsafe.Pointer(&msg))
			h.deliverDead(machPort(dn.Port))
		default:
			// Other messages are resource exceptions of a stub. Their rights stay unclaimed.
		}
	}
}

func (h *stubHost) deliverHello(msg helloMsg) {
	h.mu.Lock()
	ch, ok := h.waiters[msg.Hello.Cookie]
	delete(h.waiters, msg.Hello.Cookie)
	h.mu.Unlock()
	if !ok {
		// Nobody waits: the fork request timed out. End the orphan.
		if pid := int(msg.Hello.PID); pid > 1 {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
		if machPort(msg.Port.Name) != machPortNull {
			_ = portDeallocate(h.self, machPort(msg.Port.Name))
		}
		return
	}
	ch <- msg
}

func (h *stubHost) deliverDead(name machPort) {
	h.mu.Lock()
	p := h.procs[name]
	h.mu.Unlock()
	if p != nil {
		p.markDead()
	}
}

// command runs one command in the template and returns its result. The caller
// holds ctlMu.
func (h *stubHost) commandLocked(cmd uint32, arg, cookie uint64) (int32, error) {
	ctl := h.ctl
	atomic.StoreUint64(&ctl.Cookie, cookie)
	atomic.StoreUint64(&ctl.Arg, arg)
	atomic.StoreUint32(&ctl.Cmd, cmd)
	seq := atomic.AddUint32(&ctl.Seq, 1)
	ulockWakeAll(&ctl.Seq)
	deadline := time.Now().Add(forkTimeout)
	for ctl.loadAck() != seq {
		if h.tmpl.dead.Load() {
			return 0, errors.New("the stub template process died")
		}
		left := time.Until(deadline)
		if left <= 0 {
			return 0, errors.New("the stub template did not acknowledge a command")
		}
		ulockWait(&ctl.Ack, ctl.loadAck(), uint32(min(left, 100*time.Millisecond)/time.Microsecond))
	}
	return atomic.LoadInt32(&ctl.Result), nil
}

// userRange returns the guest address range that no host mapping of the stub
// task touches. It reads the layout of the template task, which every stub
// task inherits.
func (h *stubHost) userRange() (lo, hi uint64, err error) {
	return userRangeFromRegions(func(addr uint64) (hostRegion, bool, error) {
		return vmRegion(h.tmpl.task, addr)
	})
}

// fillPool keeps ready stub tasks in h.ready so forkProc returns without
// waiting for a template fork round-trip.
func (h *stubHost) fillPool() {
	defer h.fillWG.Done()
	for {
		select {
		case <-h.fillStop:
			return
		default:
		}
		p, err := h.forkProcFresh()
		if err != nil {
			select {
			case <-h.fillStop:
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		select {
		case h.ready <- p:
		case <-h.fillStop:
			return
		}
	}
}

// forkProc returns a ready stub task from the pool or asks the template to
// fork one. The child has dropped the channel to the Sentry and runs under the
// strict sandbox profile before the Sentry sees it.
func (h *stubHost) forkProc() (*stubProc, error) {
	defer h.startFillOnce.Do(func() {
		h.mu.Lock()
		closed := h.closed
		h.mu.Unlock()
		if !closed {
			h.fillWG.Add(1)
			go h.fillPool()
		}
	})
	for {
		select {
		case p := <-h.ready:
			if p.dead.Load() {
				h.dropProc(p)
				continue
			}
			return p, nil
		default:
		}
		return h.forkProcFresh()
	}
}

func (h *stubHost) forkProcFresh() (*stubProc, error) {
	h.ctlMu.Lock()
	defer h.ctlMu.Unlock()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("the stub host is closed")
	}
	h.cookie++
	cookie := h.cookie
	ch := make(chan helloMsg, 1)
	h.waiters[cookie] = ch
	h.mu.Unlock()
	abandon := func() {
		h.mu.Lock()
		delete(h.waiters, cookie)
		h.mu.Unlock()
	}
	res, err := h.commandLocked(cmdFork, 0, cookie)
	if err != nil {
		abandon()
		return nil, err
	}
	if res < 0 {
		abandon()
		return nil, fmt.Errorf("fork in the stub template failed with result %d", res)
	}
	select {
	case msg := <-ch:
		if err := checkHello(&msg, 1); err != nil {
			if pid := int(msg.Hello.PID); pid > 1 {
				_ = unix.Kill(pid, unix.SIGKILL)
			}
			return nil, err
		}
		p := &stubProc{task: machPort(msg.Port.Name), pid: int(msg.Hello.PID), deadCh: make(chan struct{})}
		h.mu.Lock()
		h.procs[p.task] = p
		h.mu.Unlock()
		if err := portRequestDeadName(h.self, p.task, h.recv); err != nil {
			h.dropProc(p)
			return nil, err
		}
		return p, nil
	case <-h.stop:
		abandon()
		return nil, errors.New("the stub host is closed")
	case <-time.After(forkTimeout):
		abandon()
		return nil, errors.New("the forked stub did not report in time")
	}
}

// killProc ends a stub task. The template is the parent of the task and
// signals it. The Sentry signals the task itself when the template is gone.
func (h *stubHost) killProc(p *stubProc) {
	if p.pid <= 1 {
		return
	}
	h.ctlMu.Lock()
	res, err := h.commandLocked(cmdKill, uint64(p.pid), 0)
	h.ctlMu.Unlock()
	if err != nil || res != 0 {
		_ = unix.Kill(p.pid, unix.SIGKILL)
	}
}

// dropProc ends a stub task, waits until the kernel reports it dead and
// releases its port. Waiting matters, because the caller returns the task's
// shared pages to the pool afterwards.
func (h *stubHost) dropProc(p *stubProc) {
	h.killProc(p)
	select {
	case <-p.deadCh:
	case <-time.After(deathTimeout):
	}
	h.mu.Lock()
	delete(h.procs, p.task)
	h.mu.Unlock()
	_ = portDeallocate(h.self, p.task)
}

func (h *stubHost) killPid() {
	if h.pid > 0 {
		_ = unix.Kill(h.pid, unix.SIGKILL)
		var ws unix.WaitStatus
		_, _ = unix.Wait4(h.pid, &ws, 0, nil)
		h.pid = 0
	}
}

// close terminates the template and every stub task that is still alive.
func (h *stubHost) close() error {
	h.mu.Lock()
	if h.closed {
		err := h.closeErr
		h.mu.Unlock()
		return err
	}
	h.closed = true
	h.mu.Unlock()

	close(h.fillStop)
	h.fillWG.Wait()
	for {
		select {
		case <-h.ready:
		default:
			goto drained
		}
	}
drained:
	h.mu.Lock()
	procs := make([]*stubProc, 0, len(h.procs))
	for _, p := range h.procs {
		procs = append(procs, p)
	}
	h.procs = make(map[machPort]*stubProc)
	h.mu.Unlock()

	var errs []error
	for _, p := range procs {
		if p != h.tmpl {
			h.killProc(p)
		}
		_ = portDeallocate(h.self, p.task)
	}
	// The template is a child of the Sentry, so a signal ends it and wait reaps it.
	h.killPid()
	close(h.stop)
	h.monitor.Wait()
	if h.ctlAddr != 0 {
		if err := vmDeallocate(h.self, h.ctlAddr, blockSize); err != nil {
			errs = append(errs, err)
		}
		h.ctlAddr = 0
	}
	if err := portDestroy(h.self, h.recv); err != nil {
		errs = append(errs, err)
	}
	h.closeErr = errors.Join(errs...)
	return h.closeErr
}
