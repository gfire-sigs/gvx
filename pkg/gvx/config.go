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
	"runtime"
	"strconv"
	"strings"

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
	// On darwin/arm64 it needs a Sentry built with -tags pagesize_16k. Other
	// hosts have no engine yet, and New returns ErrPlatformUnavailable there.
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

// ParsePortForward parses a "hostPort:guestPort" or "hostPort:guestPort/proto"
// specification string.
func ParsePortForward(spec string) (PortForward, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PortForward{}, errors.New("gvx: empty port forward specification")
	}
	proto := "tcp"
	if slash := strings.IndexByte(spec, '/'); slash != -1 {
		proto = strings.ToLower(strings.TrimSpace(spec[slash+1:]))
		spec = spec[:slash]
		if proto != "tcp" && proto != "udp" {
			return PortForward{}, fmt.Errorf("gvx: unsupported port forward protocol %q", proto)
		}
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 2 {
		return PortForward{}, fmt.Errorf("gvx: invalid port forward %q (expected hostPort:guestPort)", spec)
	}
	hostPort, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return PortForward{}, fmt.Errorf("gvx: invalid host port in %q: %w", spec, err)
	}
	guestPort, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
	if err != nil || guestPort == 0 {
		return PortForward{}, fmt.Errorf("gvx: invalid guest port in %q", spec)
	}
	return PortForward{
		HostPort:    uint16(hostPort),
		GuestPort:   uint16(guestPort),
		Protocol:    proto,
		BindAddress: "127.0.0.1",
	}, nil
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

	// Argv is the command vector passed to the guest process.
	Argv []string

	// Envv is the environment variable list ("KEY=VALUE") passed to the guest.
	Envv []string

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

	// DisableHostLockdown permits trusted execution without host containment.
	// Windows callers use NewProcess for containment. New rejects this configuration
	// unless DisableHostLockdown is true. macOS and Linux apply irreversible
	// containment to the caller through New.
	DisableHostLockdown bool

	processNetwork *processNetworkIO
}

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
