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
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/pkg/gvx"
)

type process struct {
	cmd    *exec.Cmd
	helper *gvx.HelperProcess
	pid    int
	exited chan struct{}    // closed after wait returns
	state  *os.ProcessState // valid after exited is closed
	tail   *stderrTail      // last 8 sanitized stderr lines
}

// defaultDriverEnv holds the fixed driver environment variables passed to the
// renderer child process before optional test-mode variables.
var defaultDriverEnv []string

// rendererCommandLine builds the argv and scrubbed environment of the renderer
// child process from opts so no ambient host variable reaches the child.
func rendererCommandLine(opts Options) (args, env []string) {
	mode := opts.Mode
	if mode == 0 {
		mode = gpuproto.ModeVenus
	}
	args = []string{opts.Path, gpuproto.ArgMode + mode.String()}
	if opts.MemoryLimit > 0 {
		args = append(args, fmt.Sprintf("%s%d", gpuproto.ArgMemoryLimit, opts.MemoryLimit))
	}
	// Keep env non-nil so exec.Cmd does not inherit os.Environ().
	env = append([]string{}, defaultDriverEnv...)
	needTestMode := opts.TestOps
	if opts.StallFences {
		args = append(args, gpuproto.ArgStallFences)
		needTestMode = true
	}
	if opts.TestWatchdogBytes > 0 {
		args = append(args, fmt.Sprintf("%s%d", gpuproto.ArgTestWatchdogBytes, opts.TestWatchdogBytes))
		needTestMode = true
	}
	if needTestMode {
		env = append(env, gpuproto.EnvTestMode+"=1")
	}
	return args, env
}

// startProcess creates the socketpair, starts the renderer with the child end
// as descriptor 3, and returns the parent end as a non-blocking UnixConn.
func startProcess(ctx context.Context, opts Options) (*process, *net.UnixConn, *os.File, error) {
	// Without ForkLock, a concurrent exec can inherit a socketpair descriptor
	// before CloseOnExec marks it close-on-exec.
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("socketpair: %w", err)
	}

	if err := unix.SetNonblock(fds[0], true); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return nil, nil, nil, fmt.Errorf("setnonblock: %w", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "gpu-renderer")
	conn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = unix.Close(fds[1])
		return nil, nil, nil, fmt.Errorf("fileconn: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		_ = unix.Close(fds[1])
		return nil, nil, nil, fmt.Errorf("unexpected connection type %T", conn)
	}

	childFile := os.NewFile(uintptr(fds[1]), "gpu-renderer-child")
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = uc.Close()
		_ = childFile.Close()
		return nil, nil, nil, fmt.Errorf("stderr pipe: %w", err)
	}

	// Pass an explicit environment so no host variable reaches the renderer.
	args, env := rendererCommandLine(opts)

	if opts.SpawnHelper != nil {
		hp, err := opts.SpawnHelper(ctx, gvx.HelperSpec{
			Name:       "gpu-renderer",
			Path:       opts.Path,
			Args:       args[1:],
			Env:        env,
			Dir:        "/",
			ExtraFiles: []*os.File{childFile},
			Stderr:     stderrW,
		})
		_ = childFile.Close()
		_ = stderrW.Close()
		if err != nil {
			_ = uc.Close()
			_ = stderrR.Close()
			return nil, nil, nil, fmt.Errorf("exec %s: %w", opts.Path, err)
		}
		proc := &process{
			helper: hp,
			pid:    hp.PID(),
			exited: make(chan struct{}),
			tail:   &stderrTail{},
		}
		return proc, uc, stderrR, nil
	}

	cmd := &exec.Cmd{
		Path:       opts.Path,
		Args:       args,
		Env:        env,
		Dir:        "/",
		Stdin:      nil,
		Stdout:     nil,
		Stderr:     stderrW,
		ExtraFiles: []*os.File{childFile},
		// Isolate the renderer in its own process group so terminal signals do
		// not reach it before Sandbox.Close runs the shutdown order.
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true},
	}

	err = cmd.Start()
	_ = childFile.Close()
	_ = stderrW.Close()
	if err != nil {
		_ = uc.Close()
		_ = stderrR.Close()
		return nil, nil, nil, fmt.Errorf("exec %s: %w", opts.Path, err)
	}

	proc := &process{
		cmd:    cmd,
		pid:    cmd.Process.Pid,
		exited: make(chan struct{}),
		tail:   &stderrTail{},
	}
	return proc, uc, stderrR, nil
}

// wait reaps the renderer process and records its exit state.
func (p *process) wait() *os.ProcessState {
	if p == nil {
		return nil
	}
	if p.helper != nil {
		err := p.helper.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			p.state = ee.ProcessState
		}
		return p.state
	}
	if p.cmd != nil {
		_ = p.cmd.Wait()
		p.state = p.cmd.ProcessState
	}
	return p.state
}

// kill sends SIGKILL to the renderer. It ignores os.ErrProcessDone.
func (p *process) kill() {
	if p == nil {
		return
	}
	if p.helper != nil {
		_ = p.helper.Kill()
		return
	}
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
}

func exitCode(p *process) int {
	if p == nil || p.state == nil || !p.state.Exited() {
		return -1
	}
	return p.state.ExitCode()
}

// exitCause builds the loss cause for an unexpected process exit. A normal
// exit returns *ExitError; a signal termination keeps the signal text without
// ExitError.
func exitCause(state *os.ProcessState) error {
	if state != nil && state.Exited() {
		return &ExitError{Code: state.ExitCode()}
	}
	return fmt.Errorf("renderer exited: %s", describeExit(state))
}

func describeExit(state *os.ProcessState) string {
	if state == nil {
		return "unknown state"
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("killed by signal %s", ws.Signal())
	}
	if state.Exited() {
		return exitCodeWords(state.ExitCode())
	}
	return state.String()
}
