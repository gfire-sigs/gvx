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

//go:build windows

package systrap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/hostlockdown"
)

// Stub creation stays outside the Sentry job, which permits one process.
// NewProcess runs this service in its parent. Direct execution starts a helper.
// The service fixes the executable and recipient process before reading requests.

const (
	// hostEnv carries the Sentry process ID to the host. Its presence makes the
	// init function of this package run the host loop instead of main.
	hostEnv = "GVX_SYSTRAP_STUBHOST"

	hostMagic   = 0x31485347 // "GSH1"
	opNewStub   = 1
	opSetDebug  = 2
	opRelease   = 3
	opSealStub  = 4
	hostReqSize = 16
	// hostProtocolVersion is the version of the pipe protocol.
	hostProtocolVersion = 1
	hostRspSize         = 48
)

// confinement names how much of the stub confinement the host applied.
type confinement uint32

const (
	// confineToken is a Low-integrity token without privileges, in a job that
	// allows one process and kills the stub on close.
	confineToken confinement = 1 << iota
	// confineWin32k removes the Win32k system call table of the stub.
	confineWin32k
	// confineAppContainer denies ungranted files and direct network access.
	confineAppContainer
)

// stubHandles is the host reply for one stub.
type stubHandles struct {
	pid, tid uint32
	proc     windows.Handle
	thread   windows.Handle
	level    confinement
}

func init() {
	if v, ok := os.LookupEnv(hostEnv); ok {
		pid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			os.Exit(2)
		}
		os.Exit(runStubHost(uint32(pid), os.Stdin, os.Stdout))
	}
}

type stubHostLoop struct {
	sentry   windows.Handle
	level    confinement
	exe      string
	children map[uint32]*hostlockdown.Process
	debug    windows.Handle
	brokered bool
}

func runStubHost(sentryPID uint32, in io.Reader, out io.Writer) int {
	sentry, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, sentryPID)
	if err != nil {
		return 3
	}
	defer windows.CloseHandle(sentry)
	if err := serveStubHost(sentry, false, in, out); err != nil {
		return 6
	}
	return 0
}

func serveStubHost(sentry windows.Handle, brokered bool, in io.Reader, out io.Writer) error {
	exe, err := writeStubImage()
	if err != nil {
		return err
	}
	defer os.Remove(exe)
	h := &stubHostLoop{sentry: sentry, brokered: brokered, exe: exe, level: confineToken | confineWin32k | confineAppContainer,
		children: make(map[uint32]*hostlockdown.Process)}
	defer func() {
		if h.debug != 0 {
			_ = windows.CloseHandle(h.debug)
			h.debug = 0
		}
		for pid := range h.children {
			h.release(pid)
		}
	}()
	if err := writeHostReply(out, 0, nil, h.level); err != nil {
		return err
	}
	for {
		var req [hostReqSize]byte
		if _, err := io.ReadFull(in, req[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if binary.LittleEndian.Uint32(req[:]) != hostMagic {
			return errors.New("invalid stub request")
		}
		op, argument := binary.LittleEndian.Uint32(req[4:]), binary.LittleEndian.Uint64(req[8:])
		var sh *stubHandles
		var requestErr error
		switch op {
		case opSetDebug:
			if h.debug != 0 || argument == 0 {
				return errors.New("invalid debug object registration")
			}
			h.debug = windows.Handle(argument)
			if brokered {
				h.debug = 0
				requestErr = windows.DuplicateHandle(sentry, windows.Handle(argument), windows.CurrentProcess(), &h.debug, 0, false, windows.DUPLICATE_SAME_ACCESS)
			}
		case opRelease:
			if argument > uint64(^uint32(0)) {
				return errors.New("invalid stub process ID")
			}
			h.release(uint32(argument))
		case opSealStub:
			child := h.children[uint32(argument)]
			if argument > uint64(^uint32(0)) || child == nil {
				return errors.New("unknown stub process ID")
			}
			requestErr = child.RemovePrivileges()
		case opNewStub:
			if argument != 0 {
				return errors.New("invalid stub creation request")
			}
			sh, requestErr = h.newStub()
		default:
			return errors.New("unknown stub request")
		}
		var errno uint32
		if requestErr != nil {
			errno = uint32(windows.ERROR_GEN_FAILURE)
			var e windows.Errno
			if errors.As(requestErr, &e) {
				errno = uint32(e)
			}
			if traceEvents {
				tracef("stub host request %d: %v", op, requestErr)
			}
		}
		if err := writeHostReply(out, errno, sh, h.level); err != nil {
			return err
		}
	}
}

func writeHostReply(out io.Writer, errno uint32, sh *stubHandles, level confinement) error {
	var rsp [hostRspSize]byte
	binary.LittleEndian.PutUint32(rsp[0:], hostMagic)
	binary.LittleEndian.PutUint32(rsp[4:], errno)
	if sh != nil {
		level = sh.level
		binary.LittleEndian.PutUint32(rsp[8:], sh.pid)
		binary.LittleEndian.PutUint32(rsp[12:], sh.tid)
		binary.LittleEndian.PutUint64(rsp[16:], uint64(sh.proc))
		binary.LittleEndian.PutUint64(rsp[24:], uint64(sh.thread))
	}
	binary.LittleEndian.PutUint32(rsp[32:], uint32(level))
	_, err := out.Write(rsp[:])
	return err
}

func (h *stubHostLoop) release(pid uint32) {
	if child := h.children[pid]; child != nil {
		_ = child.Terminate()
		if h.debug != 0 {
			_ = ntRemoveProcessDebug(windows.Handle(child.Handle()), h.debug)
		}
		_ = child.Close()
		delete(h.children, pid)
	}
}

func (h *stubHostLoop) newStub() (_ *stubHandles, err error) {
	if h.debug == 0 {
		return nil, errors.New("the Sentry sent no debug object")
	}
	if len(h.children) >= 256 {
		return nil, windows.ERROR_NOT_ENOUGH_MEMORY
	}
	child, err := hostlockdown.StartProcess(hostlockdown.ProcessOptions{
		Executable: h.exe, Suspended: true, DisableWin32k: true,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = child.Terminate()
			if h.debug != 0 {
				_ = ntRemoveProcessDebug(windows.Handle(child.Handle()), h.debug)
			}
			_ = child.Close()
		}
	}()
	process, initial := windows.Handle(child.Handle()), windows.Handle(child.InitialThread())
	if err := ntDebugActiveProcess(process, h.debug); err != nil {
		return nil, err
	}
	tid, err := getThreadID(initial)
	if err != nil {
		return nil, err
	}
	var proc, thread windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), process, h.sentry, &proc, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	if err := windows.DuplicateHandle(windows.CurrentProcess(), initial, h.sentry, &thread, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		var local windows.Handle
		if windows.DuplicateHandle(h.sentry, proc, windows.CurrentProcess(), &local, 0, false, windows.DUPLICATE_CLOSE_SOURCE|windows.DUPLICATE_SAME_ACCESS) == nil {
			_ = windows.CloseHandle(local)
		}
		return nil, err
	}
	h.children[child.ID()] = child
	return &stubHandles{pid: child.ID(), tid: uint32(tid), proc: proc, thread: thread, level: h.level}, nil
}

// stubHost is the Sentry end of the host pipe.
type stubHost struct {
	mu  sync.Mutex
	cmd *exec.Cmd
	in  io.WriteCloser
	out io.ReadCloser
	// level is the confinement that the host reported for its last stub.
	level confinement
}

// spawnStubHost starts the host process, waits until it is ready, and gives it
// a handle to the debug object.
func spawnStubHost(debug windows.Handle) (*stubHost, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the Sentry executable: %w", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), hostEnv+"="+strconv.Itoa(os.Getpid()))
	if traceEvents {
		cmd.Stderr = os.Stderr
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the stub host: %w", err)
	}
	h := &stubHost{cmd: cmd, in: in, out: out}
	// Duplicate the debug object into the host.
	hostProc, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = h.close()
		return nil, fmt.Errorf("open the stub host: %w", err)
	}
	defer windows.CloseHandle(hostProc)
	var dup windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), debug, hostProc, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = h.close()
		return nil, fmt.Errorf("give the debug object to the stub host: %w", err)
	}
	return connectStubHost(h, dup)
}

func connectStubHost(h *stubHost, debug windows.Handle) (*stubHost, error) {
	fail := func(err error) (*stubHost, error) { _ = h.close(); return nil, err }
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return fail(err)
	}
	if binary.LittleEndian.Uint32(rsp[:]) != hostMagic || binary.LittleEndian.Uint32(rsp[4:]) != 0 {
		return fail(errors.New("invalid stub ready reply"))
	}
	h.level = confinement(binary.LittleEndian.Uint32(rsp[32:]))
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opSetDebug)
	binary.LittleEndian.PutUint64(req[8:], uint64(debug))
	if _, err := h.in.Write(req[:]); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return fail(err)
	}
	if binary.LittleEndian.Uint32(rsp[:]) != hostMagic {
		return fail(errors.New("invalid debug registration reply"))
	}
	if errno := binary.LittleEndian.Uint32(rsp[4:]); errno != 0 {
		return fail(windows.Errno(errno))
	}
	return h, nil
}

// newStub asks the host for one suspended stub process.
func (h *stubHost) newStub() (*stubHandles, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opNewStub)
	if _, err := h.in.Write(req[:]); err != nil {
		return nil, fmt.Errorf("send to the stub host: %w", err)
	}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return nil, fmt.Errorf("read from the stub host: %w", err)
	}
	if binary.LittleEndian.Uint32(rsp[0:]) != hostMagic {
		return nil, errors.New("the stub host sent a malformed reply")
	}
	if errno := binary.LittleEndian.Uint32(rsp[4:]); errno != 0 {
		return nil, fmt.Errorf("the stub host could not create a stub: %w", windows.Errno(errno))
	}
	sh := &stubHandles{
		pid:    binary.LittleEndian.Uint32(rsp[8:]),
		tid:    binary.LittleEndian.Uint32(rsp[12:]),
		proc:   windows.Handle(binary.LittleEndian.Uint64(rsp[16:])),
		thread: windows.Handle(binary.LittleEndian.Uint64(rsp[24:])),
		level:  confinement(binary.LittleEndian.Uint32(rsp[32:])),
	}
	return sh, nil
}

// sealStub removes token privileges after the loader completes.
func (h *stubHost) sealStub(pid uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opSealStub)
	binary.LittleEndian.PutUint64(req[8:], uint64(pid))
	if _, err := h.in.Write(req[:]); err != nil {
		return err
	}
	var rsp [hostRspSize]byte
	if _, err := io.ReadFull(h.out, rsp[:]); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(rsp[:]) != hostMagic {
		return errors.New("invalid stub seal reply")
	}
	if errno := binary.LittleEndian.Uint32(rsp[4:]); errno != 0 {
		return windows.Errno(errno)
	}
	return nil
}

// release tells the host that the stub with the given process ID is gone.
func (h *stubHost) release(pid uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var req [hostReqSize]byte
	binary.LittleEndian.PutUint32(req[0:], hostMagic)
	binary.LittleEndian.PutUint32(req[4:], opRelease)
	binary.LittleEndian.PutUint64(req[8:], uint64(pid))
	if _, err := h.in.Write(req[:]); err != nil {
		return
	}
	var rsp [hostRspSize]byte
	_, _ = io.ReadFull(h.out, rsp[:])
}

// close stops the host. The host exits when the pipe closes, and the kernel
// kills every stub that is still alive.
func (h *stubHost) close() error {
	_ = h.in.Close()
	var err error
	if h.cmd != nil {
		err = h.cmd.Wait()
	}
	_ = h.out.Close()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return nil
	}
	return err
}
