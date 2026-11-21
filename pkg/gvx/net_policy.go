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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/oci"
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

// NetPolicyOptions selects the durable policy for a NAT sandbox.
type NetPolicyOptions struct {
	// Path names the private host store. The sandbox opens it before lockdown.
	Path string
	// Seed creates a new store exclusively. Nil opens an existing store.
	Seed *netbackend.PolicyConfig
	// ControlAddress reserves an optional loopback TCP management endpoint.
	// A TCP CheckpointListener supplies its bound address when this is zero.
	ControlAddress netip.AddrPort
	// ControlPaths lists private endpoint files, such as a token sidecar,
	// that the guest must not see. The sandbox also checks a Unix listener's path.
	ControlPaths []string
}

// NetPolicySnapshot contains the accepted policy and its instance-specific revision.
type NetPolicySnapshot struct {
	Revision string `json:"revision"`
	netbackend.PolicyConfig
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
	if c.NetPolicy.Path == "" {
		return netPolicyError("state_unavailable", "network policy requires a host store path")
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

func (m CheckpointManifest) validateNetPolicyBinding() error {
	switch m.Version {
	case CheckpointManifestVersion:
		if m.NetPolicy != nil {
			return fmt.Errorf("%w: %w", ErrCheckpointManifest, netPolicyError("state_mismatch", "a version 1 bundle cannot contain a network policy binding"))
		}
	case protectedCheckpointManifestVersion:
		binding := m.NetPolicy
		if m.NetMode != NetModeNAT || binding == nil || !validPolicyStoreID(binding.StoreID) || binding.MinGeneration == 0 {
			return fmt.Errorf("%w: %w", ErrCheckpointManifest, netPolicyError("state_mismatch", "invalid network policy binding"))
		}
	default:
		return fmt.Errorf("%w: unsupported version %d", ErrCheckpointManifest, m.Version)
	}
	return nil
}

func validPolicyStoreID(id string) bool {
	if len(id) != hex.EncodedLen(policyStoreIDBytes) || strings.ContainsAny(id, "ABCDEF") {
		return false
	}
	var decoded [policyStoreIDBytes]byte
	_, err := hex.Decode(decoded[:], []byte(id))
	return err == nil
}

func (s *Sandbox) openNetPolicy(binding *CheckpointNetPolicy, restoreDir string) error {
	opts := s.cfg.NetPolicy
	if binding != nil {
		if s.cfg.NetworkMode != NetModeNAT {
			return netPolicyError("state_mismatch", "a protected checkpoint requires NAT mode")
		}
		if opts == nil {
			return netPolicyError("state_unavailable", "a protected checkpoint requires its host policy store")
		}
		if opts.Seed != nil {
			return netPolicyError("state_mismatch", "a protected checkpoint cannot seed a policy store")
		}
	}
	if opts == nil {
		return nil
	}
	control, unixPath, err := netPolicyControlEndpoint(opts.ControlAddress, s.cfg.CheckpointListener)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	validatePaths := func() error {
		if err := s.cfg.validateNetPolicyPaths(restoreDir, unixPath); err != nil {
			return fmt.Errorf("%w: %w: %w", ErrInvalidConfig, netPolicyError("state_unavailable", "unsafe network policy path"), err)
		}
		return nil
	}
	if err := validatePaths(); err != nil {
		return err
	}
	var compiled *netbackend.CompiledPolicy
	var seed *netbackend.PolicyConfig
	if opts.Seed != nil {
		candidate := *opts.Seed
		compiled, err = netbackend.CompilePolicy(candidate)
		if err != nil {
			return err
		}
		seed = &candidate
	}
	store, err := openNetPolicyStore(opts.Path, seed)
	if err != nil {
		return fmt.Errorf("%w: %w", netPolicyError("state_unavailable", "open network policy store"), err)
	}
	s.policyStore = store
	if binding != nil && (store.id != binding.StoreID || store.generation < binding.MinGeneration) {
		return netPolicyError("state_mismatch", "the selected store does not meet the checkpoint binding")
	}
	// A new file can make an alternate filesystem name resolve.
	if seed != nil {
		if err := validatePaths(); err != nil {
			return err
		}
	}
	if compiled == nil {
		compiled, err = netbackend.CompilePolicy(store.config)
		if err != nil {
			return fmt.Errorf("%w: %w", netPolicyError("state_unavailable", "compile stored network policy"), err)
		}
	}
	s.policyRunID = rand.Text()
	s.netPolicy = netbackend.NewNATPolicy(compiled, control)
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

func (c *Config) validateNetPolicyPaths(restoreDir, unixPath string) error {
	storePath := c.NetPolicy.Path
	privatePaths := append([]string{storePath}, c.NetPolicy.ControlPaths...)
	if unixPath != "" {
		privatePaths = append(privatePaths, unixPath)
	}
	for _, controlPath := range privatePaths[1:] {
		if controlPath == "" {
			return errEmptyNetPolicyControlPath
		}
		if err := rejectNetPolicyOverlap(storePath, controlPath, false); err != nil {
			return err
		}
	}
	cache := c.OCICacheDir
	volumeRoot, _ := c.volumeRoot()
	if cache == "" {
		cache, _ = oci.DefaultCacheDir()
	}
	for _, dir := range []string{cache, volumeRoot, c.CheckpointDir, restoreDir} {
		if dir != "" {
			if err := rejectNetPolicyOverlap(storePath, dir, true); err != nil {
				return err
			}
		}
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

// NetPolicy reads the current confirmed policy of a protected NAT sandbox.
func (s *Sandbox) NetPolicy() (NetPolicySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.netPolicyStatusLocked(); err != nil {
		return NetPolicySnapshot{}, err
	}
	return s.netPolicySnapshotLocked(), nil
}

// ReplaceNetPolicy commits cfg if expected matches the current revision.
// The revision changes after both durable commit and live publication succeed.
func (s *Sandbox) ReplaceNetPolicy(expected string, cfg netbackend.PolicyConfig) (NetPolicySnapshot, error) {
	s.mu.Lock()
	err := s.netPolicyStatusLocked()
	s.mu.Unlock()
	if err != nil {
		return NetPolicySnapshot{}, err
	}
	compiled, err := netbackend.CompilePolicy(cfg)
	if err != nil {
		return NetPolicySnapshot{}, err
	}

	s.ckptMu.Lock()
	defer s.ckptMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.netPolicyStatusLocked(); err != nil {
		return NetPolicySnapshot{}, err
	}
	if expected != s.netPolicyRevisionLocked() {
		return NetPolicySnapshot{}, netPolicyError("revision_conflict", "the network policy revision changed")
	}
	if err := s.policyStore.Stage(cfg); err != nil {
		return NetPolicySnapshot{}, fmt.Errorf("%w: %w", netPolicyError("state_unavailable", "stage network policy"), err)
	}
	if err := s.netPolicy.Commit(compiled, s.policyStore.Commit); err != nil {
		s.policyCommitErr = fmt.Errorf("%w: %w", netPolicyError("commit_uncertain", "network policy requires recovery"), err)
		return NetPolicySnapshot{}, s.policyCommitErr
	}
	return s.netPolicySnapshotLocked(), nil
}

func (s *Sandbox) netPolicyStatusLocked() error {
	if s.cfg.NetworkMode != NetModeNAT {
		return netPolicyError("unsupported_mode", "network policy requires NAT mode")
	}
	if s.netPolicy == nil {
		return netPolicyError("policy_disabled", "this sandbox has no active network policy")
	}
	return s.policyCommitErr
}

func (s *Sandbox) netPolicyRevisionLocked() string {
	return s.policyRunID + ":" + strconv.FormatUint(s.policyStore.generation, 10)
}

func (s *Sandbox) netPolicySnapshotLocked() NetPolicySnapshot {
	return NetPolicySnapshot{
		Revision:     s.netPolicyRevisionLocked(),
		PolicyConfig: s.policyStore.config,
	}
}

func (s *Sandbox) checkpointNetPolicyLocked() (*CheckpointNetPolicy, error) {
	if s.policyCommitErr != nil {
		return nil, s.policyCommitErr
	}
	if s.policyStore == nil {
		return nil, nil
	}
	return &CheckpointNetPolicy{StoreID: s.policyStore.id, MinGeneration: s.policyStore.generation}, nil
}
