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

package hostlockdown

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// ErrNotConsole reports a standard file or pipe that needs no console broker.
var ErrNotConsole = errors.New("hostlockdown: input is not a console")

// ConsoleReader borrows a console file and cancels only its own synchronous reads.
// The caller must keep the file open and must not read it concurrently.
type ConsoleReader struct {
	file   *os.File
	readMu sync.Mutex
	mu     sync.Mutex
	active *consoleRead
	closed atomic.Bool
}
type consoleRead struct {
	mu       sync.Mutex
	thread   windows.Handle
	finished bool
}

var procCancelSynchronousIO = modKernel32.NewProc("CancelSynchronousIo")

func NewConsoleReader(file *os.File) (*ConsoleReader, error) {
	if file == nil {
		return nil, os.ErrInvalid
	}
	var mode uint32
	if err := windows.GetConsoleMode(windows.Handle(file.Fd()), &mode); err != nil {
		return nil, ErrNotConsole
	}
	if err := procCancelSynchronousIO.Find(); err != nil {
		return nil, err
	}
	return &ConsoleReader{file: file}, nil
}

func (c *ConsoleReader) Read(data []byte) (n int, err error) {
	if !c.readMu.TryLock() {
		return 0, errors.New("hostlockdown: console already has a reader")
	}
	defer c.readMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return 0, err
	}
	op := &consoleRead{thread: thread}
	defer func() {
		op.mu.Lock()
		op.finished = true
		err = errors.Join(err, windows.CloseHandle(op.thread))
		op.mu.Unlock()
	}()
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.active = op
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.active = nil; c.mu.Unlock() }()
	return c.file.Read(data)
}

// Close interrupts a read without closing the caller's file.
func (c *ConsoleReader) Close() error {
	c.closed.Store(true)
	c.mu.Lock()
	op := c.active
	c.mu.Unlock()
	if op == nil {
		return nil
	}
	// Keep the reading thread locked until cancellation can no longer target it.
	for {
		op.mu.Lock()
		if op.finished {
			op.mu.Unlock()
			return nil
		}
		success, _, err := procCancelSynchronousIO.Call(uintptr(op.thread))
		op.mu.Unlock()
		if success == 0 && !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return fmt.Errorf("hostlockdown: cancel console read: %w", err)
		}
		runtime.Gosched()
	}
}
