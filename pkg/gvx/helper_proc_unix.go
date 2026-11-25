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

//go:build darwin || linux || android

package gvx

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"

	"z.gfire.dev/gvx/pkg/hostlockdown"
)

// HelperProcess owns one host worker process launched before host lockdown.
type HelperProcess struct {
	name string
	cmd  *exec.Cmd
	pid  int

	doneCh  chan struct{}
	waitErr error

	mu     sync.Mutex
	closed bool
}

func spawnHelperProcess(ctx context.Context, spec HelperSpec) (*HelperProcess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if hostlockdown.IsLockedDown() {
		return nil, ErrLockdownActive
	}
	if spec.Path == "" {
		return nil, fmt.Errorf("%w: helper spec path is empty", ErrInvalidConfig)
	}

	cmd := exec.Command(spec.Path, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.ExtraFiles = spec.ExtraFiles
	cmd.Stdin = spec.Stdin
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gvx: spawn helper %q (%s): %w", spec.Name, spec.Path, err)
	}

	hp := &HelperProcess{
		name:   spec.Name,
		cmd:    cmd,
		pid:    cmd.Process.Pid,
		doneCh: make(chan struct{}),
	}
	go func() {
		hp.waitErr = cmd.Wait()
		close(hp.doneCh)
	}()
	return hp, nil
}

// Name returns the diagnostic name of the helper process.
func (h *HelperProcess) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

// PID returns the OS process identifier of the helper.
func (h *HelperProcess) PID() int {
	if h == nil {
		return 0
	}
	return h.pid
}

// Done returns a channel closed once the helper process exits and is reaped.
func (h *HelperProcess) Done() <-chan struct{} {
	if h == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.doneCh
}

// Wait blocks until the helper exits and returns its exit error, if any.
func (h *HelperProcess) Wait() error {
	if h == nil {
		return nil
	}
	<-h.doneCh
	return h.waitErr
}

// Kill terminates the helper process with SIGKILL. It is idempotent.
func (h *HelperProcess) Kill() error {
	if h == nil || h.cmd == nil || h.cmd.Process == nil {
		return nil
	}
	select {
	case <-h.doneCh:
		return nil
	default:
	}
	err := h.cmd.Process.Signal(syscall.SIGKILL)
	if err != nil && (errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM)) {
		select {
		case <-h.doneCh:
			return nil
		default:
		}
	}
	return err
}

// Close terminates the helper if still running and waits until it is reaped.
func (h *HelperProcess) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		<-h.doneCh
		return nil
	}
	h.closed = true
	h.mu.Unlock()

	select {
	case <-h.doneCh:
		return nil
	default:
	}
	killErr := h.Kill()
	<-h.doneCh
	return killErr
}
