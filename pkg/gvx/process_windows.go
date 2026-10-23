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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"z.gfire.dev/gvx/internal/sandboxrpc"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/platform/systrap"
	"z.gfire.dev/gvx/pkg/sentry/platform/whpx"
)

type processConfiguration struct {
	Argv, Envv           []string
	WorkDir, Workspace   string
	ReadOnly, TTY        bool
	LayerCount           int
	Network              NetworkMode
	IsolateLAN           bool
	PortForwards         []PortForward
	WireGuard            *netbackend.WireGuardConfig
	ConsoleInput         bool
	Platform             PlatformType
	Mounts               []Mount
	User, Hostname, Name string
	Resources            Resources
	ReadOnlyRoot         bool
}
type processResult struct {
	Status      hostlockdown.Status
	Code        int
	Error       string
	MemoryLimit bool
	Ports       []int
	Published   []PublishedPort
	Limits      LimitReport
}

type processState struct {
	mu           sync.Mutex
	child        *hostlockdown.Process
	broker       *whpx.Broker
	stubBroker   *systrap.StubBroker
	runPipe      *sandboxrpc.Pipe
	runDone      chan struct{}
	runErr       error
	network      *networkBroker
	console      *hostlockdown.ConsoleReader
	server       *sandboxrpc.Server
	control      *sandboxrpc.Pipe
	runStarted   bool
	closed       bool
	closeOnce    sync.Once
	closeErr     error
	exited       chan struct{}
	exitCode     uint32
	exitErr      error
	served       chan struct{}
	watched      chan struct{}
	outputs      sync.WaitGroup
	outputMu     sync.Mutex
	outputErrors []error
	outputFiles  []*os.File
}

func startProcess(ctx context.Context, worker WorkerCommand, cfg Config) (_ *ProcessSandbox, err error) {
	if cfg.DisableHostLockdown {
		return nil, fmt.Errorf("%w: NewProcess requires host lockdown", ErrInvalidConfig)
	}
	if cfg.Platform != PlatformAuto && cfg.Platform != PlatformWHPX && cfg.Platform != PlatformSystrap {
		return nil, fmt.Errorf("%w: unsupported Windows process platform", ErrInvalidConfig)
	}
	if cfg.Platform == PlatformSystrap && runtime.GOARCH != "arm64" {
		return nil, fmt.Errorf("%w: confined systrap requires windows/arm64", ErrPlatformUnavailable)
	}
	if worker.Executable == "" {
		return nil, fmt.Errorf("%w: worker executable is required", ErrInvalidConfig)
	}
	if cfg.Stdin != nil {
		if file, ok := cfg.Stdin.(*os.File); !ok || file == nil {
			return nil, fmt.Errorf("%w: process stdin must be an *os.File", ErrInvalidConfig)
		}
	}
	prepared := &Sandbox{cfg: cfg}
	defer func() { err = errors.Join(err, prepared.Close()) }()
	if err := prepared.initOCILayers(ctx); err != nil {
		return nil, err
	}
	cfg = prepared.cfg
	cfg.PortForwards = prepared.effectivePortForwards()
	cfg.PublishAll = false
	if cfg.User == "" && prepared.resolvedImg != nil {
		cfg.User = prepared.resolvedImg.Config.User
	}
	cfg.Mounts = append([]Mount(nil), cfg.Mounts...)
	for i, mount := range cfg.Mounts {
		if mount.Kind == MountTmpfs {
			continue
		}
		dir, err := prepared.prepareHostDir(mount)
		if err != nil {
			return nil, err
		}
		dir, err = filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, err
		}
		mount.Kind, mount.HostPath, mount.VolumeName, mount.CreateHostPathIfMissing = MountBind, dir, "", false
		cfg.Mounts[i] = mount
	}
	if cfg.WorkspacePath != "" {
		absolute, err := filepath.Abs(cfg.WorkspacePath)
		if err != nil {
			return nil, fmt.Errorf("gvx: resolve workspace: %w", err)
		}
		cfg.WorkspacePath, err = filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("gvx: resolve workspace: %w", err)
		}
	}
	cfg.TTY = cfg.TTY || isHostTerminalReader(cfg.Stdin)
	if prepared.resolvedImg != nil && (cfg.WorkDir == "" || cfg.WorkDir == "/") && prepared.resolvedImg.Config.WorkingDir != "" {
		cfg.WorkDir = prepared.resolvedImg.Config.WorkingDir
	}
	state := &processState{}
	defer func() {
		if err != nil {
			err = errors.Join(err, state.close())
		}
	}()
	state.network, err = newNetworkBroker(ctx, &cfg)
	if err != nil {
		return nil, err
	}
	var temporary []*os.File
	keep := make(map[*os.File]bool)
	defer func() {
		for _, file := range temporary {
			if !keep[file] {
				_ = file.Close()
			}
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		r, w, e := os.Pipe()
		if e == nil {
			temporary = append(temporary, r, w)
		}
		return r, w, e
	}
	controlRead, controlWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	replyRead, replyWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	brokerRead, brokerWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	requestRead, requestWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	state.control = &sandboxrpc.Pipe{Reader: replyRead, Output: controlWrite}
	keep[replyRead], keep[controlWrite] = true, true
	input, ok := cfg.Stdin.(*os.File)
	if ok {
		state.console, err = hostlockdown.NewConsoleReader(input)
		if errors.Is(err, hostlockdown.ErrNotConsole) {
			err = nil
		} else if err != nil {
			return nil, err
		}
		if state.console != nil {
			ok = false
		}
	}
	if !ok {
		input, err = os.Open(os.DevNull)
		if err != nil {
			return nil, err
		}
		temporary = append(temporary, input)
	}
	output := func(writer io.Writer) (*os.File, error) {
		if writer == nil {
			writer = io.Discard
		}
		r, w, e := pipe()
		if e != nil {
			return nil, e
		}
		state.outputFiles = append(state.outputFiles, r)
		keep[r] = true
		state.outputs.Add(1)
		go func() {
			defer state.outputs.Done()
			defer r.Close()
			_, err := io.Copy(writer, r)
			if err != nil {
				state.outputMu.Lock()
				state.outputErrors = append(state.outputErrors, err)
				state.outputMu.Unlock()
			}
		}()
		return w, nil
	}
	stdout, err := output(cfg.Stdout)
	if err != nil {
		return nil, err
	}
	stderr, err := output(cfg.Stderr)
	if err != nil {
		return nil, err
	}
	stubRead, stubWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	stubReplyRead, stubReplyWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	files := []*os.File{controlRead, replyWrite, brokerRead, requestWrite, stubWrite, stubReplyRead}
	for _, layer := range prepared.layerHandles {
		duplicate, err := layer.Dup()
		if err != nil {
			return nil, err
		}
		handle, err := duplicate.Release()
		if err != nil {
			return nil, err
		}
		file := os.NewFile(handle, "gvx EROFS layer")
		temporary = append(temporary, file)
		files = append(files, file)
	}
	var mounts []hostlockdown.HostMount
	for _, mount := range cfg.mountList() {
		if mount.Kind != MountTmpfs {
			mounts = append(mounts, hostlockdown.HostMount{Path: mount.HostPath, ReadOnly: mount.ReadOnly})
		}
	}
	state.child, err = hostlockdown.StartProcess(hostlockdown.ProcessOptions{Executable: worker.Executable, Arguments: worker.Arguments, Stdin: input, Stdout: stdout, Stderr: stderr, Files: files, Mounts: mounts, CPUQuotaMillis: cfg.Resources.CPUMillis})
	if err != nil {
		return nil, err
	}
	state.exited = make(chan struct{})
	go func() { state.exitCode, state.exitErr = state.child.Wait(); close(state.exited) }()
	for _, file := range files {
		_ = file.Close()
	}
	for _, file := range temporary {
		if file == stdout || file == stderr {
			_ = file.Close()
		}
	}
	if cfg.Platform == PlatformAuto || cfg.Platform == PlatformWHPX {
		state.broker, err = whpx.NewBroker(state.child.Handle())
		if err != nil {
			if cfg.Platform != PlatformAuto || runtime.GOARCH != "arm64" || !errors.Is(err, whpx.ErrUnsupported) {
				return nil, err
			}
			cfg.Platform = PlatformSystrap
		} else {
			cfg.Platform = PlatformWHPX
		}
	}
	if cfg.Platform == PlatformSystrap {
		state.stubBroker, err = systrap.NewStubBroker(state.child.Handle(), stubRead, stubReplyWrite)
		if err != nil {
			return nil, err
		}
		keep[stubRead], keep[stubReplyWrite] = true, true
	} else if state.broker != nil {
		state.runPipe = &sandboxrpc.Pipe{Reader: stubRead, Output: stubReplyWrite}
		keep[stubRead], keep[stubReplyWrite] = true, true
		state.runDone = make(chan struct{})
		go func() {
			state.runErr = state.broker.ServeRuns(state.runPipe)
			close(state.runDone)
		}()
	} else {
		_ = stubRead.Close()
		_ = stubReplyWrite.Close()
	}
	connection := &sandboxrpc.Pipe{Reader: requestRead, Output: brokerWrite}
	state.server, err = sandboxrpc.NewServer(connection, "Network", state.network)
	if err != nil {
		return nil, err
	}
	keep[requestRead], keep[brokerWrite] = true, true
	if state.broker != nil {
		if err := state.server.Register("Hypervisor", state.broker); err != nil {
			return nil, err
		}
	}
	if state.console != nil {
		if err := state.server.Register("Input", &consoleInputService{reader: state.console}); err != nil {
			return nil, err
		}
	}
	state.served = make(chan struct{})
	go func() { state.server.Serve(); close(state.served) }()
	state.watched = make(chan struct{})
	go func() { <-state.exited; state.shutdown(); close(state.watched) }()
	configuration := processConfiguration{Argv: cfg.Argv, Envv: cfg.Envv, WorkDir: cfg.WorkDir, Workspace: cfg.WorkspacePath, ReadOnly: cfg.WorkspaceReadOnly, TTY: cfg.TTY, LayerCount: len(prepared.layerHandles), Network: cfg.NetworkMode, IsolateLAN: cfg.IsolateLAN, PortForwards: cfg.PortForwards, WireGuard: cfg.WireGuardConfig, Platform: cfg.Platform, Mounts: cfg.Mounts, User: cfg.User, Hostname: cfg.Hostname, Name: cfg.Name, Resources: cfg.Resources, ReadOnlyRoot: cfg.ReadOnlyRoot}
	if cfg.NetworkMode != NetModeWireGuard {
		configuration.WireGuard = nil
	}
	configuration.ConsoleInput = state.console != nil
	var reply processResult
	ready := make(chan error, 1)
	go func() {
		if err := sandboxrpc.WriteMessage(state.control, configuration); err != nil {
			ready <- err
			return
		}
		ready <- sandboxrpc.ReadMessage(state.control, &reply)
	}()
	select {
	case err = <-ready:
	case <-ctx.Done():
		state.shutdown()
		<-ready
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("gvx: initialize worker: %w", err)
	}
	if reply.Error != "" {
		return nil, fmt.Errorf("gvx: initialize worker: %s", reply.Error)
	}
	return &ProcessSandbox{state: state, status: reply.Status, ports: reply.Ports, published: reply.Published, limits: reply.Limits, platform: string(cfg.Platform)}, nil
}

func (p *processState) run(ctx context.Context) (int, error) {
	p.mu.Lock()
	if p.closed || p.runStarted {
		p.mu.Unlock()
		return 0, errors.New("gvx: worker is closed or has already run")
	}
	p.runStarted = true
	p.mu.Unlock()
	var result processResult
	done := make(chan error, 1)
	go func() {
		if err := sandboxrpc.WriteMessage(p.control, "run"); err != nil {
			done <- err
			return
		}
		done <- sandboxrpc.ReadMessage(p.control, &result)
	}()
	select {
	case err := <-done:
		if err != nil {
			return 0, errors.Join(fmt.Errorf("gvx: run worker: %w", err), p.close())
		}
		select {
		case <-p.exited:
		case <-ctx.Done():
			return 0, errors.Join(ctx.Err(), p.close())
		}
		p.outputs.Wait()
		if outputErr := errors.Join(p.outputErrors...); outputErr != nil {
			return result.Code, outputErr
		}
		if result.MemoryLimit {
			return result.Code, fmt.Errorf("%w: %s", ErrMemoryLimit, result.Error)
		}
		if result.Error != "" {
			return result.Code, errors.New(result.Error)
		}
		if p.exitErr != nil {
			return result.Code, fmt.Errorf("gvx: wait for worker: %w", p.exitErr)
		}
		if p.exitCode != 0 {
			return result.Code, fmt.Errorf("gvx: worker exit %d", p.exitCode)
		}
		return result.Code, nil
	case <-ctx.Done():
		p.shutdown()
		<-done
		return 0, errors.Join(ctx.Err(), p.close())
	}
}

func (p *processState) shutdown() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.mu.Unlock()
		var errs []error
		if p.child != nil {
			errs = append(errs, p.child.Terminate())
		}
		if p.console != nil {
			errs = append(errs, p.console.Close())
		}
		if p.network != nil {
			errs = append(errs, p.network.Close())
		}
		if p.broker != nil {
			errs = append(errs, p.broker.Close())
		}
		if p.runPipe != nil {
			_ = p.runPipe.Close()
		}
		if p.stubBroker != nil {
			errs = append(errs, p.stubBroker.Close())
		}
		if p.child != nil {
			errs = append(errs, p.child.Close())
		}
		if p.control != nil {
			errs = append(errs, p.control.Close())
		}
		if p.server != nil {
			errs = append(errs, p.server.Close())
		}
		p.closeErr = errors.Join(errs...)
	})
}

func (p *processState) close() error {
	p.shutdown()
	if p.exited != nil {
		<-p.exited
	}
	if p.served != nil {
		<-p.served
	}
	if p.runDone != nil {
		<-p.runDone
	}
	if p.watched != nil {
		<-p.watched
	}
	p.outputs.Wait()
	for _, file := range p.outputFiles {
		_ = file.Close()
	}
	return errors.Join(append([]error{p.closeErr, p.runErr}, p.outputErrors...)...)
}

func workerHandle(index int) (uintptr, error) {
	value := os.Getenv(fmt.Sprintf("GVX_WORKER_FD_%d", index))
	handle, err := strconv.ParseUint(value, 10, 64)
	if err != nil || handle == 0 {
		return 0, fmt.Errorf("gvx: missing worker descriptor %d", index)
	}
	return uintptr(handle), nil
}

func serveProcess(ctx context.Context, options WorkerOptions) (err error) {
	if err := hostlockdown.RequireAppContainer(); err != nil {
		return err
	}
	var files []*os.File
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for index := range 6 {
		handle, err := workerHandle(index)
		if err != nil {
			return err
		}
		files = append(files, os.NewFile(handle, "gvx worker pipe"))
	}
	control := &sandboxrpc.Pipe{Reader: files[0], Output: files[1]}
	var configuration processConfiguration
	if err := sandboxrpc.ReadMessage(control, &configuration); err != nil {
		return err
	}
	client := sandboxrpc.NewClient(&sandboxrpc.Pipe{Reader: files[2], Output: files[3]})
	proxy := &processNetworkProxy{client: client}
	defer proxy.pending.Wait()
	defer client.Close()
	if configuration.WireGuard != nil {
		configuration.WireGuard.ListenPacket = proxy.listenPacket
	}
	var guestInput io.Reader = struct{ io.Reader }{os.Stdin}
	if configuration.ConsoleInput {
		guestInput = &consoleInputProxy{client: client}
	}
	sandbox := &Sandbox{cfg: Config{Platform: configuration.Platform, NetworkMode: configuration.Network, IsolateLAN: configuration.IsolateLAN, PortForwards: configuration.PortForwards, WireGuardConfig: configuration.WireGuard, processNetwork: proxy.networkIO(), Argv: configuration.Argv, Envv: configuration.Envv, WorkDir: configuration.WorkDir, WorkspacePath: configuration.Workspace, WorkspaceReadOnly: configuration.ReadOnly, TTY: configuration.TTY, Stdin: guestInput, Stdout: os.Stdout, Stderr: os.Stderr, Mounts: configuration.Mounts, User: configuration.User, Hostname: configuration.Hostname, Name: configuration.Name, Resources: configuration.Resources, ReadOnlyRoot: configuration.ReadOnlyRoot}, platName: string(configuration.Platform)}
	defer func() { err = errors.Join(err, sandbox.Close()) }()
	initialize := func() error {
		var err error
		switch configuration.Platform {
		case PlatformWHPX:
			sandbox.plat, err = whpx.NewBrokeredWithRuns(client, &sandboxrpc.Pipe{Reader: files[5], Output: files[4]})
		case PlatformSystrap:
			sandbox.plat, err = systrap.NewBrokered(files[4], files[5])
		default:
			return errors.New("gvx: invalid worker platform")
		}
		if err != nil {
			return err
		}
		for index := range configuration.LayerCount {
			handle, err := workerHandle(6 + index)
			if err != nil {
				return err
			}
			layer, err := fd.NewHostHandle(handle)
			if err != nil {
				return err
			}
			sandbox.layerHandles = append(sandbox.layerHandles, layer)
		}
		if err := sandbox.openMounts(); err != nil {
			return err
		}
		if err := sandbox.initNetstack(); err != nil {
			return err
		}
		sandbox.memFile, err = createKernelMemoryFile()
		if err != nil {
			return err
		}
		sandbox.attachChunkMemory()
		sandbox.lockdown, err = hostlockdown.Apply(hostlockdown.Options{CPUQuotaMillis: configuration.Resources.CPUMillis})
		if configuration.Platform == PlatformSystrap {
			sandbox.lockdown.CPUQuotaEnforced = false
		}
		return err
	}
	if err := initialize(); err != nil {
		_ = sandboxrpc.WriteMessage(control, processResult{Error: err.Error()})
		return err
	}
	if options.AfterLockdown != nil {
		if err := options.AfterLockdown(ctx, sandbox); err != nil {
			_ = sandboxrpc.WriteMessage(control, processResult{Error: err.Error()})
			return err
		}
	}
	var ports []int
	for index := range configuration.PortForwards {
		ports = append(ports, sandbox.BoundPort(index))
	}
	if err := sandboxrpc.WriteMessage(control, processResult{Status: sandbox.lockdown, Ports: ports, Published: sandbox.PublishedPorts(), Limits: sandbox.Limits()}); err != nil {
		return err
	}
	var command string
	if err := sandboxrpc.ReadMessage(control, &command); err != nil {
		return err
	}
	if command != "run" {
		return errors.New("gvx: invalid worker command")
	}
	code, runErr := sandbox.Run(ctx)
	result := processResult{Code: code, MemoryLimit: errors.Is(runErr, ErrMemoryLimit)}
	if runErr != nil {
		result.Error = runErr.Error()
	}
	return sandboxrpc.WriteMessage(control, result)
}
