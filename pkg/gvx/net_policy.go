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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"z.gfire.dev/gvx/pkg/netbackend"
)

// NetPolicyConfig contains both rule files and bandwidth limits.
type NetPolicyConfig = netbackend.PolicyConfig

// NetPolicyLimit sets one directional bandwidth limit.
type NetPolicyLimit = netbackend.PolicyLimit

// NetPolicyError identifies a policy validation or availability failure.
type NetPolicyError = netbackend.PolicyError

// MaxNetPolicyRules bounds the size in bytes of each rule file.
const MaxNetPolicyRules = netbackend.MaxPolicyRules

// ParseNetPolicyLimit parses unlimited or a finite directional limit.
func ParseNetPolicyLimit(s string) (NetPolicyLimit, error) {
	return netbackend.ParsePolicyLimit(s)
}

// NetPolicyOptions selects the initial policy for a NAT sandbox.
type NetPolicyOptions struct {
	// Policy supplies both rule files and both directional limits.
	Policy NetPolicyConfig
	// ControlAddress reserves an optional loopback TCP management endpoint.
	// A TCP CheckpointListener supplies its bound address when this is zero.
	ControlAddress netip.AddrPort
	// ControlPaths lists private endpoint files, such as a token sidecar,
	// that the guest must not see. The sandbox also checks a Unix listener's path.
	ControlPaths []string
}

// NetPolicyErrorCode returns a stable policy error code, or internal.
func NetPolicyErrorCode(err error) string {
	var policyErr *netbackend.PolicyError
	if errors.As(err, &policyErr) && policyErr != nil && policyErr.Code != "" {
		return policyErr.Code
	}
	return "internal"
}

func netPolicyError(code, detail string) error {
	return &netbackend.PolicyError{Code: code, Detail: detail}
}

var errEmptyNetPolicyControlPath = errors.New("empty control file path")

func (c *Config) validateNetPolicyConfig() error {
	if c.NetPolicy == nil {
		return nil
	}
	if c.NetworkMode != NetModeNAT {
		return netPolicyError("unsupported_mode", "network policy requires NAT mode")
	}
	if c.StreamInterceptor != nil {
		return netPolicyError("invalid_policy", "protected NAT does not allow a stream interceptor")
	}
	for _, pf := range c.PortForwards {
		if pf.HostSocket != "" {
			return netPolicyError("invalid_policy", "protected NAT does not allow Unix publications")
		}
		if pf.Protocol == "udp" {
			if addr, err := netip.ParseAddr(pf.BindAddress); err == nil && addr.Unmap().IsUnspecified() {
				return netPolicyError("invalid_policy", "protected NAT requires a concrete UDP publication address")
			}
		}
	}
	return nil
}

func (s *Sandbox) initNetPolicy(restoreDir string) error {
	opts := s.cfg.NetPolicy
	s.cfg.NetPolicy = nil
	if opts == nil {
		return nil
	}
	control, unixPath, err := netPolicyControlEndpoint(opts.ControlAddress, s.cfg.CheckpointListener)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	if err := s.cfg.validateNetPolicyPaths(restoreDir, unixPath, opts.ControlPaths); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrInvalidConfig, netPolicyError("invalid_policy", "unsafe network policy path"), err)
	}
	policy := opts.Policy
	compiled, err := netbackend.CompilePolicy(policy)
	if err != nil {
		return err
	}
	s.netPolicy = netbackend.NewNATPolicy(compiled, control)
	s.netPolicyConfig = policy
	return nil
}

func netPolicyControlEndpoint(configured netip.AddrPort, listener net.Listener) (netip.AddrPort, string, error) {
	var unixPath string
	if listener != nil {
		addr := listener.Addr()
		if addr == nil {
			return netip.AddrPort{}, "", netPolicyError("invalid_policy", "the control listener has no bound address")
		}
		switch addr.Network() {
		case "tcp", "tcp4", "tcp6":
			bound, err := netip.ParseAddrPort(addr.String())
			if err != nil || (configured != (netip.AddrPort{}) && unmapAddrPort(configured) != unmapAddrPort(bound)) {
				return netip.AddrPort{}, "", netPolicyError("invalid_policy", "the control address does not match the bound TCP listener")
			}
			configured = bound
		case "unix":
			unixPath = addr.String()
			if unixPath == "" || strings.HasPrefix(unixPath, "@") || strings.HasPrefix(unixPath, "\x00") {
				return netip.AddrPort{}, "", netPolicyError("invalid_policy", "a protected Unix control listener requires a file path")
			}
		default:
			return netip.AddrPort{}, "", netPolicyError("invalid_policy", "protected control requires a loopback TCP or Unix listener")
		}
	}
	if configured != (netip.AddrPort{}) {
		configured = unmapAddrPort(configured)
		if !configured.Addr().IsLoopback() || configured.Addr().Zone() != "" || configured.Port() == 0 {
			return netip.AddrPort{}, "", netPolicyError("invalid_policy", "the control address must name a bound loopback TCP port")
		}
	}
	return configured, unixPath, nil
}

func unmapAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (c *Config) validateNetPolicyPaths(restoreDir, unixPath string, controlPaths []string) error {
	for _, path := range controlPaths {
		if path == "" {
			return errEmptyNetPolicyControlPath
		}
	}
	privatePaths := controlPaths[:len(controlPaths):len(controlPaths)]
	if unixPath != "" {
		privatePaths = append(privatePaths, unixPath)
	}
	for _, dir := range []string{c.CheckpointDir, restoreDir} {
		if dir != "" {
			privatePaths = append(privatePaths, dir,
				filepath.Join(dir, checkpointManifestFileName),
				filepath.Join(dir, checkpointStateFileName),
				filepath.Join(dir, checkpointPagesMetaFileName),
				filepath.Join(dir, checkpointPagesFileName),
			)
		}
	}
	mounts := c.mountList()
	if c.RootVolume != "" {
		mount, err := parseRootVolumeMount(c.RootVolume)
		if err != nil {
			return err
		}
		mounts = append(mounts, mount)
	}
	for _, m := range mounts {
		if err := c.validateNetPolicyMountPaths(m, privatePaths); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateNetPolicyMountPaths(m Mount, privatePaths []string) error {
	var path, upper string
	var dir bool
	var err error
	switch m.Kind {
	case MountBind:
		path, dir = m.HostPath, true
	case MountVolume:
		driver, err := c.resolveVolumeDriver(m)
		if err != nil {
			return err
		}
		if driver == DriverHostfs {
			root, err := c.volumeRoot()
			if err != nil {
				return err
			}
			path, dir = filepath.Join(root, m.VolumeName), true
			break
		}
		path, err = c.volumeImagePath(m)
		if err != nil {
			return err
		}
	case MountOverlay:
		path, err = c.volumeImagePath(m)
		if err != nil {
			return err
		}
		if m.hasOverlayUpper() {
			upper, err = c.volumeImagePath(m.overlayUpperMount())
			if err != nil {
				return err
			}
		}
	case MountTmpfs:
		return nil
	}
	for _, private := range privatePaths {
		if err := rejectNetPolicyOverlap(private, path, dir); err != nil {
			return err
		}
		if upper != "" {
			if err := rejectNetPolicyOverlap(private, upper, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectNetPolicyOverlap(private, source string, dir bool) error {
	privateAbs, err := filepath.Abs(private)
	if err != nil {
		return err
	}
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	privateAbs = resolveSymlinkPrefix(privateAbs)
	sourceAbs = resolveSymlinkPrefix(sourceAbs)
	if rel, err := filepath.Rel(sourceAbs, privateAbs); err == nil {
		if rel == "." || (dir && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return fmt.Errorf("private path %q overlaps %q", private, source)
		}
	}
	sourceInfo, err := os.Stat(sourceAbs)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Compare identity too: pathnames alone miss hard links and alternate mount roots.
	for p := privateAbs; ; p = filepath.Dir(p) {
		info, err := os.Stat(p)
		if err == nil && os.SameFile(sourceInfo, info) {
			return fmt.Errorf("private path %q overlaps %q", private, source)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !dir || !sourceInfo.IsDir() || filepath.Dir(p) == p {
			return nil
		}
	}
}

// NetPolicy reads the active policy of a protected NAT sandbox.
func (s *Sandbox) NetPolicy() (NetPolicyConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.netPolicyStatusLocked(); err != nil {
		return NetPolicyConfig{}, err
	}
	return s.netPolicyConfig, nil
}

// ReplaceNetPolicy atomically replaces both rule files and both directional limits.
func (s *Sandbox) ReplaceNetPolicy(cfg NetPolicyConfig) error {
	s.mu.Lock()
	err := s.netPolicyStatusLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	compiled, err := netbackend.CompilePolicy(cfg)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.netPolicyStatusLocked(); err != nil {
		return err
	}
	if err := s.netPolicy.Commit(compiled); err != nil {
		return err
	}
	s.netPolicyConfig = cfg
	return nil
}

func (s *Sandbox) netPolicyStatusLocked() error {
	if s.cfg.NetworkMode != NetModeNAT {
		return netPolicyError("unsupported_mode", "network policy requires NAT mode")
	}
	if s.netPolicy == nil {
		return netPolicyError("policy_disabled", "this sandbox has no active network policy")
	}
	return nil
}
