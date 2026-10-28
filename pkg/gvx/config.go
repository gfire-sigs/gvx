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

// Package gvx provides the embeddable Go SDK for running isolated Linux ELF64
// binaries and multi-arch OCI container images on Windows and macOS.
package gvx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"

	"z.gfire.dev/gvx/pkg/netbackend"
)

// PlatformType selects the guest execution backend.
type PlatformType string

const (
	// PlatformAuto selects the hardware hypervisor of the host OS (whpx on
	// Windows, hvf on macOS) and falls back to systrap when the hypervisor
	// cannot start. New returns an error when no backend starts.
	PlatformAuto PlatformType = "auto"
	// PlatformWHPX selects the Windows Hypervisor Platform backend.
	PlatformWHPX PlatformType = "whpx"
	// PlatformHVF selects the macOS Hypervisor.framework backend.
	PlatformHVF PlatformType = "hvf"
	// PlatformSystrap selects the native stub-subprocess backend of SPEC 3.3.
	// It runs on Windows and Linux. macOS runs on Hypervisor.framework only, so
	// New returns ErrPlatformUnavailable there.
	PlatformSystrap PlatformType = "systrap"
)

// NetworkMode selects the Netstack egress backend.
type NetworkMode string

const (
	// NetModeNAT selects Track A: L4 Go net NAT and inbound port forwarding.
	NetModeNAT NetworkMode = "nat"
	// NetModeWireGuard selects Track B: L3 in-memory wireguard-go tunnel.
	NetModeWireGuard NetworkMode = "wg"
	// NetModeNone disables external network egress (loopback only).
	NetModeNone NetworkMode = "none"

	// NetworkNAT is an alias for NetModeNAT.
	NetworkNAT = NetModeNAT
	// NetworkWireGuard is an alias for NetModeWireGuard.
	NetworkWireGuard = NetModeWireGuard
	// NetworkNone is an alias for NetModeNone.
	NetworkNone = NetModeNone
)

// PortForward specifies an inbound host-to-guest port forward (-p host:guest).
type PortForward struct {
	HostPort    uint16
	GuestPort   uint16
	Protocol    string
	BindAddress string
}

// ParsePortForward parses a Docker publish specification: "guest",
// "host:guest", "ip:host:guest", or "ip::guest", with an optional "/tcp" or
// "/udp" suffix. A host port of zero, and a specification with only a guest
// port, ask for a free host port. The default bind address is 127.0.0.1. An
// IPv6 address is written in brackets. A port range is not supported.
func ParsePortForward(spec string) (PortForward, error) {
	rule, err := netbackend.ParsePortForwardSpec(spec, true, true)
	if err != nil {
		return PortForward{}, fmt.Errorf("gvx: %w", err)
	}
	return PortForward{
		HostPort:    rule.HostPort,
		GuestPort:   rule.GuestPort,
		Protocol:    rule.Proto,
		BindAddress: rule.HostIP,
	}, nil
}

// Resources limits what the guest may use. A zero field means no limit.
type Resources struct {
	// MemoryBytes is the largest memory use of the guest. A value above zero
	// must be at least MinMemoryLimit. The sandbox kills a guest that passes it.
	MemoryBytes int64

	// CPUMillis is the CPU quota in thousandths of a CPU. The guest sees that
	// many CPUs rounded up. Windows also caps the CPU time of the host process.
	CPUMillis int64
}

// ErrInvalidConfig marks a Config that New rejects before it opens any host
// handle. Callers separate usage errors from runtime failures with errors.Is.
var ErrInvalidConfig = errors.New("gvx: invalid configuration")

// Config configures a gvx Sandbox instance.
type Config struct {
	// Platform selects the execution backend ("auto", "whpx", "hvf", or "systrap").
	Platform PlatformType

	// NetworkMode selects the network backend ("nat", "wg", or "none").
	NetworkMode NetworkMode

	// IsolateLAN blocks outbound NAT connections to RFC1918, loopback, and
	// link-local LAN addresses when NetworkMode is NetModeNAT.
	IsolateLAN bool

	// PortForwards lists inbound host-to-guest port forwardings (-p host:guest).
	PortForwards []PortForward

	// WireGuardConfigPath is the path to a WireGuard INI configuration file
	// when NetworkMode is NetModeWireGuard.
	WireGuardConfigPath string

	// WireGuardConfig provides an in-memory WireGuard configuration when
	// NetworkMode is NetModeWireGuard.
	WireGuardConfig *netbackend.WireGuardConfig

	// StreamInterceptor is an optional host-side L4/L7 proxy hook for outbound
	// NAT streams.
	StreamInterceptor netbackend.StreamInterceptor

	// OCIImage specifies an OCI image reference, OCI archive tar path, or
	// built-in image name (e.g. "alpine:3.20", "nginx:alpine", "python:3.12-alpine").
	OCIImage string

	// OCILayerTars provides raw in-memory .tar or .tar.gz layer streams to
	// compile into cached <sha256>.erofs layers and mount in lower-to-upper order.
	OCILayerTars [][]byte

	// OCICacheDir overrides the default host EROFS layer cache directory.
	OCICacheDir string

	// RegistryBaseURL specifies an optional HTTP/HTTPS OCI registry base URL.
	RegistryBaseURL string

	// BinaryPath specifies a host path to a Linux ELF64 binary to execute.
	BinaryPath string

	// ELFBytes provides an in-memory Linux ELF64 binary to execute directly.
	ELFBytes []byte

	// WorkspacePath specifies the host directory to mount at /workspace via
	// fsimpl/hostfs (os.OpenRoot + .gvx_meta).
	WorkspacePath string

	// WorkspaceReadOnly mounts /workspace in read-only mode.
	WorkspaceReadOnly bool

	// Mounts lists extra guest mounts: bind mounts of host directories, named
	// volumes, and tmpfs mounts. WorkspacePath and WorkspaceReadOnly stay the
	// shorthand for the bind mount at /workspace, so no entry of Mounts may use
	// /workspace when WorkspacePath is set.
	Mounts []Mount

	// ReadOnlyRoot mounts the root file system of the guest in read-only mode
	// after the guest setup. /proc, /sys, /dev, /dev/shm, /dev/pts, and every
	// mount of WorkspacePath and Mounts keep their own access flags.
	ReadOnlyRoot bool

	// Argv is the command vector passed to the guest process.
	Argv []string

	// Entrypoint replaces the image Entrypoint when EntrypointSet is true. An
	// empty Entrypoint with EntrypointSet clears the image Entrypoint. Docker
	// rules apply: Argv, when it is not empty, wins over Entrypoint and Cmd.
	Entrypoint    []string
	EntrypointSet bool

	// Cmd replaces the image Cmd. The guest runs the Entrypoint followed by Cmd.
	// An override of the Entrypoint drops the image Cmd.
	Cmd []string

	// Envv is the environment variable list ("KEY=VALUE") that the sandbox
	// merges over the image Env. A key in Envv replaces the same key of the image.
	Envv []string

	// User is a Docker user specification: "name", "uid", "user:group", or
	// "uid:gid". The sandbox resolves names in the /etc/passwd and /etc/group
	// of the guest. The empty string means the image User, and then root.
	User string

	// Hostname is the hostname of the guest. The default is "gvx".
	Hostname string

	// Name is an optional container name that follows the Docker rule
	// [a-zA-Z0-9][a-zA-Z0-9_.-]+. The sandbox uses it as the container ID of the
	// kernel. A run has no other state, so the name has no further effect.
	Name string

	// Resources limits the memory and the CPU of the guest.
	Resources Resources

	// PublishAll publishes every port that the image declares with EXPOSE to a
	// free port of 127.0.0.1. It needs the nat network mode and an image.
	PublishAll bool

	// WorkDir is the initial guest working directory (defaults to "/workspace"
	// when WorkspacePath is set, or "/").
	WorkDir string

	// Stdin is the guest standard input reader.
	Stdin io.Reader

	// Stdout is the guest standard output writer.
	Stdout io.Writer

	// Stderr is the guest standard error writer.
	Stderr io.Writer

	// TTY allocates a pseudo-terminal line discipline for guest stdio (FD 0, 1, 2).
	TTY bool

	// Architecture is the Linux guest architecture ("amd64" or "arm64").
	// It selects the OCI manifest and the required ELF machine type. It
	// defaults to runtime.GOARCH. The hardware backends run only the host
	// architecture.
	Architecture string

	// DisableHostLockdown skips pkg/hostlockdown. New applies the lockdown
	// (Windows RestrictedToken and JobObject, or macOS Seatbelt) by default,
	// after it opens all host handles. The lockdown is irreversible for
	// the host process, so embedders that keep using the process for other
	// work must set this field.
	DisableHostLockdown bool
}

// defaultHostname is the guest hostname when Config.Hostname is empty.
const defaultHostname = "gvx"

var (
	containerNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)
	// hostnamePattern accepts what Linux sethostname takes: at most 64 bytes.
	hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,64}$`)
)

// normalize applies defaults and rejects contradictory settings before New
// opens any host handle. Every rejection wraps ErrInvalidConfig.
func (c *Config) normalize() error {
	if c.Platform == "" {
		c.Platform = PlatformAuto
	}
	switch c.Platform {
	case PlatformAuto, PlatformWHPX, PlatformHVF, PlatformSystrap:
	default:
		return fmt.Errorf("%w: unsupported platform %q", ErrInvalidConfig, c.Platform)
	}

	if c.Architecture == "" {
		c.Architecture = runtime.GOARCH
	}
	if _, err := elfMachine(c.Architecture); err != nil {
		return err
	}
	if c.Architecture != runtime.GOARCH {
		if runtime.GOOS == "linux" {
			return fmt.Errorf("%w: guest architecture %s cannot run on a %s Linux host: the upstream systrap platform runs only the host architecture", ErrInvalidConfig, c.Architecture, runtime.GOARCH)
		}
		if c.Platform != PlatformSystrap {
			return fmt.Errorf("%w: guest architecture %s needs -platform=systrap on a %s host: the hardware backends run only the host architecture", ErrInvalidConfig, c.Architecture, runtime.GOARCH)
		}
	}

	if c.NetworkMode == "" {
		c.NetworkMode = NetModeNAT
	}
	switch c.NetworkMode {
	case NetModeNAT, NetModeWireGuard, NetModeNone:
	default:
		return fmt.Errorf("%w: unsupported network mode %q", ErrInvalidConfig, c.NetworkMode)
	}
	if len(c.PortForwards) > 0 && c.NetworkMode != NetModeNAT {
		return fmt.Errorf("%w: port forwards need network mode %q, got %q", ErrInvalidConfig, NetModeNAT, c.NetworkMode)
	}
	if c.NetworkMode == NetModeWireGuard && c.WireGuardConfig == nil && c.WireGuardConfigPath == "" {
		return fmt.Errorf("%w: network mode %q needs WireGuardConfig or WireGuardConfigPath", ErrInvalidConfig, NetModeWireGuard)
	}

	if _, _, _, err := splitUserSpec(c.User); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if c.Name != "" && !containerNamePattern.MatchString(c.Name) {
		return fmt.Errorf("%w: invalid container name %q (want [a-zA-Z0-9][a-zA-Z0-9_.-]+)", ErrInvalidConfig, c.Name)
	}
	if c.Hostname == "" {
		c.Hostname = defaultHostname
	}
	if !hostnamePattern.MatchString(c.Hostname) {
		return fmt.Errorf("%w: invalid hostname %q (want 1 to 64 characters from a-z, A-Z, 0-9, dot, and hyphen)", ErrInvalidConfig, c.Hostname)
	}
	if m := c.Resources.MemoryBytes; m < 0 || (m > 0 && m < MinMemoryLimit) {
		return fmt.Errorf("%w: memory limit %d bytes is invalid: use 0 or at least %d", ErrInvalidConfig, m, MinMemoryLimit)
	}
	if q := c.Resources.CPUMillis; q < 0 || q > int64(runtime.NumCPU())*1000 {
		return fmt.Errorf("%w: CPU quota %d is invalid: use 0 to %d thousandths of a CPU", ErrInvalidConfig, q, runtime.NumCPU()*1000)
	}
	if c.PublishAll && c.NetworkMode != NetModeNAT {
		return fmt.Errorf("%w: publishing the exposed ports needs network mode %q, got %q", ErrInvalidConfig, NetModeNAT, c.NetworkMode)
	}
	if err := c.validateMounts(); err != nil {
		return err
	}

	if c.Stdout == nil {
		c.Stdout = os.Stdout
	}
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	if c.WorkDir == "" {
		if c.WorkspacePath != "" {
			c.WorkDir = "/workspace"
		} else {
			c.WorkDir = "/"
		}
	}
	return nil
}
