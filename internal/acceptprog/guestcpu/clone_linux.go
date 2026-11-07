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

//go:build linux && (amd64 || arm64)

package guestcpu

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// CloneThreadFlags are the flags of clone for a thread that shares the address
// space, the file system information, the descriptors, the signal handlers,
// and the System V semaphore adjustments of its creator. The kernel stores the
// thread ID in the word that ptid names before clone returns, and it clears
// that word and wakes a futex wait on it when the thread exits.
const CloneThreadFlags = syscall.CLONE_VM | syscall.CLONE_FS | syscall.CLONE_FILES |
	syscall.CLONE_SIGHAND | syscall.CLONE_THREAD | syscall.CLONE_SYSVSEM |
	syscall.CLONE_PARENT_SETTID | syscall.CLONE_CHILD_CLEARTID

const (
	childStackSize = 16 << 10
	// childStackReserve is the number of bytes above the stack pointer of the
	// child that hold its frame and its slots.
	childStackReserve = 256
)

// The slots of the child must fit in the reserved bytes.
const _ = uint(childStackReserve - (slotExecEnvp + 8))

// ChildStack is the stack of the child that Clone creates. The child finds in
// it the address of the State that it stores, and the arguments of execve when
// SetExec set them.
type ChildStack struct {
	mem []byte
	off int
}

// NewChildStack allocates a stack for a child of Clone. The child stores its
// registers in out.
func NewChildStack(out *State) (*ChildStack, error) {
	mem, err := syscall.Mmap(-1, 0, childStackSize, syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	c := &ChildStack{mem: mem, off: (childStackSize - childStackReserve) &^ 15}
	c.put(slotOut, uint64(uintptr(unsafe.Pointer(out))))
	return c, nil
}

func (c *ChildStack) put(slot int, v uint64) {
	binary.LittleEndian.PutUint64(c.mem[c.off+slot:], v)
}

// SP returns the stack pointer that the child gets.
func (c *ChildStack) SP() uintptr { return uintptr(unsafe.Pointer(&c.mem[c.off])) }

// SetExec makes the child call execve(path, argv, envp) and not store its
// registers. The arguments are the addresses of a NUL-terminated string and of
// two arrays of such strings, each with a nil pointer at the end. The caller
// keeps them alive until the child ends.
func (c *ChildStack) SetExec(path, argv, envp uintptr) {
	c.put(slotExecPath, uint64(path))
	c.put(slotExecArgv, uint64(argv))
	c.put(slotExecEnvp, uint64(envp))
}

// Close frees the stack. The child must have ended.
func (c *ChildStack) Close() { _ = syscall.Munmap(c.mem) }

// Clone loads in, runs the system call clone that in describes (see
// State.SetClone), and stores the registers of the new child in the State that
// its ChildStack names. The parent stores its registers after the call in
// parent. The child ends when it stored its registers and calls exit. The
// result register of parent holds the child ID. Clone has the same
// requirements as Run.
func Clone(in, parent *State) { runClone(in, parent) }

func runClone(in, out *State)
