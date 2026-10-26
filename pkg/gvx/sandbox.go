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
	"runtime"
	"sync"

	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvf"
	"z.gfire.dev/gvx/pkg/sentry/platform/whpx"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Sandbox coordinates the execution backend (whpx or hvf), OCI EROFS
// overlay layers, hostfs, volume and tmpfs mounts, Dual-Track Netstack, and host
// process self-lockdown.
type Sandbox struct {
	mu            sync.Mutex
	cfg           Config
	plat          platform.Platform
	platName      string
	memFile       *pgalloc.MemoryFile
	resolvedImg   *oci.ResolvedImage
	layerHandles  []*fd.HostHandle
	workspace     *hostfs.Workspace
	workspaces    []*hostfs.Workspace
	volumes       []*ext4lite.Volume
	mounts        []sandboxMount
	netStack      *stack.Stack
	natForwarder  *netbackend.NATForwarder
	portForwarder *netbackend.PortForwarder
	wgEndpoint    *netbackend.WireGuardEndpoint
	wgPeerPort    uint16
	lockdown      hostlockdown.Status
	// forwards holds the port forwards that initNetstack bound, in rule order:
	// the caller list, then the ports that PublishAll added.
	forwards []PortForward
	closed   bool
}

// New initializes a Sandbox. It opens the execution platform, the EROFS layer
// handles, the os.Root of every bind and volume mount, the network sockets, and the kernel
// MemoryFile, then locks down the host process unless
// Config.DisableHostLockdown is set. Every host handle exists before the
// lockdown call because the lockdown denies new host file opens.
func New(ctx context.Context, cfg Config) (*Sandbox, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	sb := &Sandbox{cfg: cfg}

	cleanup := func(cause error) (*Sandbox, error) {
		return nil, errors.Join(cause, sb.Close())
	}

	plat, platName, err := openPlatform(cfg.Platform, !cfg.DisableHostLockdown)
	if err != nil {
		return cleanup(err)
	}
	sb.plat = plat
	sb.platName = platName

	if err := sb.initOCILayers(ctx); err != nil {
		return cleanup(err)
	}

	if err := sb.openMounts(); err != nil {
		return cleanup(err)
	}

	if err := sb.initNetstack(); err != nil {
		return cleanup(err)
	}

	mf, err := createKernelMemoryFile()
	if err != nil {
		return cleanup(err)
	}
	sb.memFile = mf
	sb.attachChunkMemory()

	if !cfg.DisableHostLockdown {
		st, err := hostlockdown.Apply(sb.lockdownOptions())
		if err != nil {
			return cleanup(fmt.Errorf("gvx: apply host lockdown: %w", err))
		}
		sb.lockdown = st
		if tb, ok := sb.plat.(interface{ SetThreadInit(func() error) }); ok {
			tb.SetThreadInit(hostlockdown.BindThread)
		}
	}

	return sb, nil
}

// ErrPlatformUnavailable reports that the requested execution backend has no
// implementation on the current host.
var ErrPlatformUnavailable = errors.New("gvx: execution platform unavailable")

// opener starts one execution backend and returns it with its name.
type opener func() (platform.Platform, string, error)

// openPlatform opens the requested backend. PlatformAuto prefers the hardware
// hypervisor of the host OS and falls back to systrap (SPEC section 1) when
// the hypervisor cannot initialize. An explicit PlatformSystrap returns the
// engine error. The lockdown argument tells the backend to bind vCPU threads
// to the lockdown token.
func openPlatform(requested PlatformType, lockdown bool) (platform.Platform, string, error) {
	hardware := func() (platform.Platform, string, error) {
		return nil, "", fmt.Errorf("%w: no hypervisor backend for %s", ErrPlatformUnavailable, runtime.GOOS)
	}
	switch runtime.GOOS {
	case "windows":
		hardware = func() (platform.Platform, string, error) { return openWHPX(lockdown) }
	case "darwin":
		hardware = openHVF
	}
	switch requested {
	case PlatformWHPX:
		return openWHPX(lockdown)
	case PlatformHVF:
		return openHVF()
	case PlatformSystrap:
		return openSystrap()
	case PlatformAuto:
		return openAuto(hardware, openSystrap)
	default:
		return nil, "", fmt.Errorf("%w: unknown platform %q", ErrInvalidConfig, requested)
	}
}

// openAuto starts the hardware backend and falls back to the fallback backend
// when the hardware backend fails. When both fail, the error reports both.
func openAuto(hardware, fallback opener) (platform.Platform, string, error) {
	p, name, hwErr := hardware()
	if hwErr == nil {
		return p, name, nil
	}
	p, name, fbErr := fallback()
	if fbErr == nil {
		return p, name, nil
	}
	return nil, "", fmt.Errorf("gvx: no execution backend available: %w", errors.Join(hwErr, fbErr))
}

// openWHPX opens the Windows Hypervisor Platform backend. With lockdown on,
// every vCPU thread binds the restricted token of hostlockdown.Apply before it
// runs guest code.
func openWHPX(lockdown bool) (platform.Platform, string, error) {
	var opts whpx.Options
	if lockdown {
		opts.ThreadInit = hostlockdown.BindThread
	}
	p, err := whpx.NewWithOptions(opts)
	if err != nil {
		return nil, "", fmt.Errorf("gvx: open %s backend: %w", whpx.PlatformName, err)
	}
	return p, whpx.PlatformName, nil
}

func openHVF() (platform.Platform, string, error) {
	p, err := hvf.New()
	if err != nil {
		return nil, "", fmt.Errorf("gvx: open %s backend: %w", hvf.PlatformName, err)
	}
	return p, hvf.PlatformName, nil
}

// lockdownOptions maps the network mode to the host lockdown profile. NAT
// needs arbitrary outbound dials. WireGuard needs only its pre-bound UDP
// socket to reach the peer port. The none mode gets no outbound access.
func (s *Sandbox) lockdownOptions() hostlockdown.Options {
	opts := hostlockdown.Options{
		CPUQuotaMillis:       s.cfg.Resources.CPUMillis,
		Mounts:               s.hostMounts(),
		AllowOutboundNet:     s.cfg.NetworkMode == NetModeNAT,
		InstallSyscallFilter: s.syscallFilter(),
	}
	if s.cfg.NetworkMode == NetModeWireGuard && s.wgPeerPort != 0 {
		opts.OutboundUDPPorts = []uint16{s.wgPeerPort}
	}
	return opts
}

// PlatformName returns the active platform backend name ("whpx" or "hvf").
func (s *Sandbox) PlatformName() string {
	return s.platName
}

// LockdownStatus reports the host containment that New enforced. The zero
// Status means that Config.DisableHostLockdown skipped the lockdown.
func (s *Sandbox) LockdownStatus() hostlockdown.Status {
	return s.lockdown
}

// Stack returns the Sandbox's pure-Go Netstack instance.
func (s *Sandbox) Stack() *stack.Stack {
	return s.netStack
}

// Workspace returns the hostfs.Workspace handle of the mount at /workspace. It
// returns nil when no bind or volume mount uses /workspace.
func (s *Sandbox) Workspace() *hostfs.Workspace {
	return s.workspace
}

// LayerHandles returns the pre-opened read-only EROFS HostHandles.
func (s *Sandbox) LayerHandles() []*fd.HostHandle {
	return s.layerHandles
}

// PublishedPort is one host port that forwards to a guest port.
type PublishedPort struct {
	GuestPort uint16
	Protocol  string // "tcp" or "udp"
	HostAddr  string // the bind address, such as "127.0.0.1"
	HostPort  uint16 // the port that the host socket really uses
}

// PublishedPorts lists the bound port forwards, in rule order: the forwards of
// Config.PortForwards first, then the image ports that Config.PublishAll added.
// A forward with host port zero shows the free port that the host chose. It is
// empty before New binds the sockets, and for a mode other than nat.
func (s *Sandbox) PublishedPorts() []PublishedPort {
	if s.portForwarder == nil {
		return nil
	}
	rules := s.portForwarder.BoundRules()
	out := make([]PublishedPort, 0, len(rules))
	for _, r := range rules {
		out = append(out, PublishedPort{GuestPort: r.GuestPort, Protocol: r.Proto, HostAddr: r.HostIP, HostPort: r.HostPort})
	}
	return out
}

// effectivePortForwards returns Config.PortForwards followed by one forward to
// a free port of 127.0.0.1 for each image port that Config.PublishAll adds. A
// port that Config.PortForwards already forwards stays as the caller wrote it.
func (s *Sandbox) effectivePortForwards() []PortForward {
	out := append([]PortForward(nil), s.cfg.PortForwards...)
	if !s.cfg.PublishAll || s.resolvedImg == nil {
		return out
	}
	forwarded := make(map[string]bool, len(out))
	for _, f := range out {
		forwarded[fmt.Sprintf("%d/%s", f.GuestPort, f.Protocol)] = true
	}
	for _, p := range s.resolvedImg.Config.ExposedPortList() {
		if key := fmt.Sprintf("%d/%s", p.Port, p.Protocol); !forwarded[key] {
			out = append(out, PortForward{GuestPort: p.Port, Protocol: p.Protocol, BindAddress: "127.0.0.1"})
		}
	}
	return out
}

// LimitReport says which resource limits of Config.Resources the sandbox enforces.
type LimitReport struct {
	// Memory is true when the sandbox kills a guest that passes the memory limit.
	Memory bool
	// CPUCount is true when the guest sees only the CPUs of the quota.
	CPUCount bool
	// CPUTime is true when the host OS caps the CPU time of the sandbox. Only
	// Windows does, and only when the lockdown is on.
	CPUTime bool
}

// Limits reports how the sandbox enforces Config.Resources. A limit that the
// Config does not set is false.
func (s *Sandbox) Limits() LimitReport {
	return LimitReport{
		Memory:   s.cfg.Resources.MemoryBytes > 0,
		CPUCount: s.cfg.Resources.CPUMillis > 0,
		CPUTime:  s.lockdown.CPUQuotaEnforced,
	}
}

// BoundPort returns the bound host TCP/UDP port for the idx-th PortForward rule.
func (s *Sandbox) BoundPort(idx int) int {
	if s.portForwarder == nil {
		return 0
	}
	rules := s.portForwarder.BoundRules()
	if idx < 0 || idx >= len(rules) {
		return 0
	}
	return int(rules[idx].HostPort)
}

// Wait executes the sandboxed guest process and waits for completion.
func (s *Sandbox) Wait(ctx context.Context) (int, error) {
	return s.Run(ctx)
}

// Run executes the configured Linux ELF64 binary or OCI container command
// inside the Sentry kernel and returns its Linux exit code.
func (s *Sandbox) Run(ctx context.Context) (int, error) {
	if s.portForwarder != nil && s.netStack != nil {
		s.portForwarder.Start(s.netStack)
	}
	return s.runWithKernel(ctx, s.cfg.Argv)
}

// Close releases all host handles owned by the Sandbox: port forwarders,
// WireGuard endpoint, Netstack, the os.Root of every mount, EROFS layer handles, and
// the hypervisor platform.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var errs []error
	if s.portForwarder != nil {
		if err := s.portForwarder.Close(); err != nil {
			errs = append(errs, err)
		}
		s.portForwarder = nil
	}

	if s.natForwarder != nil {
		if err := s.natForwarder.Close(); err != nil {
			errs = append(errs, err)
		}
		s.natForwarder = nil
	}

	if s.wgEndpoint != nil {
		if err := s.wgEndpoint.Close(); err != nil {
			errs = append(errs, err)
		}
		s.wgEndpoint = nil
		s.netStack = nil
	}

	if s.netStack != nil {
		s.netStack.Close()
		s.netStack = nil
	}

	if err := s.closeMounts(); err != nil {
		errs = append(errs, err)
	}

	for _, hh := range s.layerHandles {
		if err := hh.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.layerHandles = nil

	if s.resolvedImg != nil {
		if err := s.resolvedImg.Close(); err != nil {
			errs = append(errs, err)
		}
		s.resolvedImg = nil
	}

	if s.memFile != nil {
		s.memFile.Destroy()
		s.memFile = nil
	}

	if s.plat != nil {
		if closer, ok := s.plat.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		s.plat = nil
	}

	return errors.Join(errs...)
}
