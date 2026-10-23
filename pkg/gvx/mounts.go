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
	"encoding/csv"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

// MountKind selects the backing store of a Mount.
type MountKind string

const (
	// MountBind mounts a host directory through hostfs.
	MountBind MountKind = "bind"
	// MountVolume mounts a named volume through hostfs. The volume is a host
	// directory below the gvx cache directory.
	MountVolume MountKind = "volume"
	// MountTmpfs mounts a memory-backed tmpfs.
	MountTmpfs MountKind = "tmpfs"
)

// Mount describes one extra guest mount. New opens the host directory of a
// bind or volume mount before the host lockdown.
type Mount struct {
	// Kind selects the backing store.
	Kind MountKind

	// HostPath is the host directory of a bind mount. A relative path is
	// relative to the working directory of the host process.
	HostPath string

	// VolumeName names a volume. It matches [a-zA-Z0-9][a-zA-Z0-9_.-]*.
	VolumeName string

	// GuestPath is the absolute, clean mount point in the guest. It is not "/".
	// It is not /proc, /sys, or /dev, and it is not below them, except below
	// /dev/shm.
	GuestPath string

	// ReadOnly mounts the guest path in read-only mode.
	ReadOnly bool

	// TmpfsSizeBytes limits a tmpfs mount. Zero selects the default limit of
	// the Sentry tmpfs. A bind or volume mount must leave it zero.
	TmpfsSizeBytes int64

	// CreateHostPathIfMissing creates the host directory of a bind mount when
	// it does not exist. New creates it before the host lockdown. Without it, a
	// missing directory is an error.
	CreateHostPathIfMissing bool
}

// workspaceGuestPath is the mount point of Config.WorkspacePath.
const workspaceGuestPath = "/workspace"

// volumeNamePattern is the set of valid volume names.
var volumeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// reservedGuestDirs are the guest directories that the kernel mounts itself.
var reservedGuestDirs = []string{"/proc", "/sys", "/dev"}

// ParseVolume parses the value of a -v flag: src:dst[:ro|rw]. A source without
// a path separator that is not absolute names a volume. Any other source is a
// host directory, which New creates when it is missing. A Windows drive letter
// in the source is part of the source: C:\data:/data:ro.
func ParseVolume(spec string) (Mount, error) {
	src, dst, mode, err := splitVolumeSpec(spec)
	if err != nil {
		return Mount{}, err
	}
	if !strings.HasPrefix(dst, "/") {
		return Mount{}, fmt.Errorf("gvx: volume %q: the guest path %q must be absolute", spec, dst)
	}
	m := Mount{GuestPath: dst}
	switch mode {
	case "", "rw":
	case "ro":
		m.ReadOnly = true
	default:
		return Mount{}, fmt.Errorf("gvx: volume %q: unsupported mode %q (use ro or rw)", spec, mode)
	}
	if !isHostPathSource(src) {
		if !volumeNamePattern.MatchString(src) {
			return Mount{}, fmt.Errorf("gvx: volume %q: invalid volume name %q", spec, src)
		}
		m.Kind = MountVolume
		m.VolumeName = src
		return m, nil
	}
	m.Kind = MountBind
	m.HostPath = src
	m.CreateHostPathIfMissing = true
	return m, nil
}

// splitVolumeSpec splits src:dst[:mode]. It keeps the colon of a Windows
// drive letter inside the source.
func splitVolumeSpec(spec string) (src, dst, mode string, err error) {
	parts := strings.Split(spec, ":")
	if hasDrivePrefix(spec) && len(parts) >= 3 && !isPlainVolumeSplit(parts) {
		parts = append([]string{parts[0] + ":" + parts[1]}, parts[2:]...)
	}
	switch len(parts) {
	case 2:
		src, dst = parts[0], parts[1]
	case 3:
		src, dst, mode = parts[0], parts[1], parts[2]
	default:
		return "", "", "", fmt.Errorf("gvx: invalid volume %q (expected src:dst[:ro|rw])", spec)
	}
	if src == "" || dst == "" {
		return "", "", "", fmt.Errorf("gvx: invalid volume %q: source and destination must not be empty", spec)
	}
	return src, dst, mode, nil
}

// isPlainVolumeSplit reports whether a spec such as c:/data:ro reads as a
// volume name, a guest path, and a mode. It settles the one ambiguity between
// a one-letter volume name and a drive letter.
func isPlainVolumeSplit(parts []string) bool {
	if !strings.HasPrefix(parts[1], "/") {
		return false
	}
	return len(parts) == 2 || len(parts) == 3 && (parts[2] == "ro" || parts[2] == "rw")
}

// hasDrivePrefix reports whether s starts with a Windows drive letter and a
// separator, as in C:\ or C:/.
func hasDrivePrefix(s string) bool {
	if len(s) < 3 || s[1] != ':' || (s[2] != '\\' && s[2] != '/') {
		return false
	}
	c := s[0] | 0x20
	return c >= 'a' && c <= 'z'
}

// isHostPathSource reports whether a volume source names a host directory.
func isHostPathSource(src string) bool {
	return strings.ContainsAny(src, `/\`) || filepath.IsAbs(src) || hasDrivePrefix(src)
}

// ParseMount parses the value of a --mount flag. The keys are type (bind,
// volume, or tmpfs; volume when absent), src or source, dst, destination, or
// target, readonly or ro, and tmpfs-size. A bind source must already exist.
func ParseMount(spec string) (Mount, error) {
	fields, err := csv.NewReader(strings.NewReader(spec)).Read()
	if err != nil {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, err)
	}
	var (
		kind     = MountVolume
		src, dst string
		size     string
		readOnly bool
	)
	for _, field := range fields {
		key, value, hasValue := strings.Cut(field, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		switch key {
		case "type":
			kind = MountKind(strings.ToLower(strings.TrimSpace(value)))
		case "src", "source":
			src = value
		case "dst", "destination", "target":
			dst = value
		case "readonly", "ro":
			readOnly = true
			if hasValue {
				if readOnly, err = strconv.ParseBool(strings.TrimSpace(value)); err != nil {
					return Mount{}, fmt.Errorf("gvx: invalid mount %q: bad value for %s: %w", spec, key, err)
				}
			}
		case "tmpfs-size":
			size = value
		default:
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: unsupported key %q", spec, key)
		}
	}
	if dst == "" {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: dst is required", spec)
	}
	m := Mount{Kind: kind, GuestPath: dst, ReadOnly: readOnly}
	switch kind {
	case MountBind, MountVolume:
		if src == "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: src is required for type=%s", spec, kind)
		}
		if size != "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: tmpfs-size needs type=tmpfs", spec)
		}
		if kind == MountBind {
			m.HostPath = src
			return m, nil
		}
		if !volumeNamePattern.MatchString(src) {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: invalid volume name %q", spec, src)
		}
		m.VolumeName = src
	case MountTmpfs:
		if src != "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: type=tmpfs takes no src", spec)
		}
		if size != "" {
			if m.TmpfsSizeBytes, err = parseTmpfsSize(size); err != nil {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, err)
			}
		}
	default:
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: unsupported type %q (use bind, volume, or tmpfs)", spec, kind)
	}
	return m, nil
}

// ParseTmpfs parses the value of a --tmpfs flag: /path[:option,...]. The
// options are size=N, ro, and rw. N is a byte count with an optional unit b,
// k, m, or g, which are binary multiples.
func ParseTmpfs(spec string) (Mount, error) {
	dst, opts, hasOpts := strings.Cut(spec, ":")
	if dst == "" {
		return Mount{}, fmt.Errorf("gvx: invalid tmpfs %q: the path is empty", spec)
	}
	m := Mount{Kind: MountTmpfs, GuestPath: dst}
	if !hasOpts {
		return m, nil
	}
	for _, opt := range strings.Split(opts, ",") {
		key, value, hasValue := strings.Cut(strings.TrimSpace(opt), "=")
		switch {
		case key == "ro" && !hasValue:
			m.ReadOnly = true
		case key == "rw" && !hasValue:
			m.ReadOnly = false
		case key == "size" && hasValue:
			size, err := parseTmpfsSize(value)
			if err != nil {
				return Mount{}, fmt.Errorf("gvx: invalid tmpfs %q: %w", spec, err)
			}
			m.TmpfsSizeBytes = size
		default:
			return Mount{}, fmt.Errorf("gvx: invalid tmpfs %q: unsupported option %q", spec, opt)
		}
	}
	return m, nil
}

// parseTmpfsSize parses a positive byte count with an optional unit b, k, m,
// or g. The units are binary multiples.
func parseTmpfsSize(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	multiplier := int64(1)
	if s != "" {
		switch s[len(s)-1] {
		case 'b':
			s = s[:len(s)-1]
		case 'k':
			multiplier, s = 1<<10, s[:len(s)-1]
		case 'm':
			multiplier, s = 1<<20, s[:len(s)-1]
		case 'g':
			multiplier, s = 1<<30, s[:len(s)-1]
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, errors.New("the size must be a positive number with an optional unit b, k, m, or g")
	}
	if n > math.MaxInt64/multiplier {
		return 0, errors.New("the size is too large")
	}
	return n * multiplier, nil
}

// validateMounts rejects a bad Mounts entry, a duplicate guest path, and a
// mount at /workspace together with WorkspacePath. Every rejection wraps
// ErrInvalidConfig.
func (c *Config) validateMounts() error {
	guestPaths := make(map[string]struct{}, len(c.Mounts)+1)
	if c.WorkspacePath != "" {
		guestPaths[workspaceGuestPath] = struct{}{}
	}
	for i, m := range c.Mounts {
		if err := m.validate(); err != nil {
			return fmt.Errorf("%w: mount %d (%s): %w", ErrInvalidConfig, i, m.GuestPath, err)
		}
		if _, dup := guestPaths[m.GuestPath]; dup {
			if m.GuestPath == workspaceGuestPath && c.WorkspacePath != "" {
				return fmt.Errorf("%w: mount %d at %s conflicts with WorkspacePath", ErrInvalidConfig, i, m.GuestPath)
			}
			return fmt.Errorf("%w: two mounts use the guest path %s", ErrInvalidConfig, m.GuestPath)
		}
		guestPaths[m.GuestPath] = struct{}{}
	}
	return nil
}

// validate checks one mount. The caller adds the context to the error.
func (m Mount) validate() error {
	if err := validateGuestPath(m.GuestPath); err != nil {
		return err
	}
	if m.TmpfsSizeBytes < 0 || m.TmpfsSizeBytes > 0 && m.Kind != MountTmpfs {
		return errors.New("TmpfsSizeBytes must be zero or positive and applies to tmpfs mounts only")
	}
	if m.CreateHostPathIfMissing && m.Kind != MountBind {
		return errors.New("CreateHostPathIfMissing applies to bind mounts only")
	}
	switch m.Kind {
	case MountBind:
		if m.VolumeName != "" {
			return errors.New("a bind mount takes no VolumeName")
		}
		return m.validateBindSource()
	case MountVolume:
		if m.HostPath != "" {
			return errors.New("a volume mount takes no HostPath")
		}
		if !volumeNamePattern.MatchString(m.VolumeName) {
			return fmt.Errorf("invalid volume name %q", m.VolumeName)
		}
	case MountTmpfs:
		if m.HostPath != "" || m.VolumeName != "" {
			return errors.New("a tmpfs mount takes no HostPath or VolumeName")
		}
	default:
		return fmt.Errorf("unsupported mount kind %q", m.Kind)
	}
	return nil
}

// validateBindSource requires an existing directory. A missing directory is
// valid when CreateHostPathIfMissing is set.
func (m Mount) validateBindSource() error {
	if m.HostPath == "" {
		return errors.New("a bind mount needs HostPath")
	}
	info, err := os.Stat(m.HostPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if m.CreateHostPathIfMissing {
			return nil
		}
		return fmt.Errorf("bind source %q does not exist", m.HostPath)
	case err != nil:
		return fmt.Errorf("bind source %q: %w", m.HostPath, err)
	case !info.IsDir():
		return fmt.Errorf("bind source %q is not a directory: bind mounts of files are not supported", m.HostPath)
	}
	return nil
}

// validateGuestPath requires an absolute, clean path that is not "/" and that
// the kernel does not own.
func validateGuestPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New("the guest path must be absolute")
	case path.Clean(p) != p:
		return errors.New("the guest path must be clean (no trailing slash, empty element, or dot element)")
	case p == "/":
		return errors.New("the guest path must not be /")
	}
	if strings.HasPrefix(p, "/dev/shm/") {
		return nil
	}
	for _, dir := range reservedGuestDirs {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return fmt.Errorf("the guest path must not be %s or below it", dir)
		}
	}
	return nil
}

// hasHostDirs reports whether the guest uses any host directory. The Linux
// seccomp filter needs the host filesystem rules in that case.
func (c Config) hasHostDirs() bool {
	if c.WorkspacePath != "" {
		return true
	}
	for _, m := range c.Mounts {
		if m.Kind != MountTmpfs {
			return true
		}
	}
	return false
}

// volumeRoot returns the directory that holds the named volumes. It lies next
// to the default layer cache directory. When OCICacheDir overrides the layer
// cache, it lies below that directory.
func (c Config) volumeRoot() (string, error) {
	if c.OCICacheDir != "" {
		return filepath.Join(c.OCICacheDir, "volumes"), nil
	}
	layers, err := oci.DefaultCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(layers), "volumes"), nil
}

// sandboxMount is a Mount that New has prepared. A bind or volume mount holds
// its absolute host directory and its open hostfs workspace.
type sandboxMount struct {
	Mount
	hostPath  string
	workspace *hostfs.Workspace
}

// mountList returns every guest mount: the WorkspacePath mount first, then
// Mounts in order.
func (c Config) mountList() []Mount {
	list := make([]Mount, 0, len(c.Mounts)+1)
	if c.WorkspacePath != "" {
		list = append(list, Mount{Kind: MountBind, HostPath: c.WorkspacePath, GuestPath: workspaceGuestPath, ReadOnly: c.WorkspaceReadOnly})
	}
	return append(list, c.Mounts...)
}

// openMounts prepares the host directories, opens one hostfs workspace for
// each bind or volume mount, and records the mounts in the order that the
// guest mounts them. A directory that two mounts share with the same access
// shares one workspace, so two flush loops never write the same metadata file.
// openMounts must run before the host lockdown.
func (s *Sandbox) openMounts() error {
	type workspaceKey struct {
		dir      string
		readOnly bool
	}
	shared := make(map[workspaceKey]*hostfs.Workspace)
	for _, m := range s.cfg.mountList() {
		sm := sandboxMount{Mount: m}
		if m.Kind != MountTmpfs {
			dir, err := s.prepareHostDir(m)
			if err != nil {
				return err
			}
			sm.hostPath = dir
			key := workspaceKey{dir: dir, readOnly: m.ReadOnly}
			if resolved, err := filepath.EvalSymlinks(dir); err == nil {
				key.dir = resolved
			}
			ws, ok := shared[key]
			if !ok {
				if ws, err = hostfs.OpenWorkspace(dir, m.ReadOnly); err != nil {
					return fmt.Errorf("gvx: open mount %s from %q: %w", m.GuestPath, dir, err)
				}
				shared[key] = ws
				s.workspaces = append(s.workspaces, ws)
			}
			sm.workspace = ws
		}
		s.mounts = append(s.mounts, sm)
		if m.GuestPath == workspaceGuestPath {
			s.workspace = sm.workspace
		}
	}
	sortMountsByDepth(s.mounts)
	return nil
}

// prepareHostDir returns the absolute host directory of a bind or volume
// mount. It creates the directory when the mount asks for it. A volume
// directory gets mode 0700.
func (s *Sandbox) prepareHostDir(m Mount) (string, error) {
	if m.Kind == MountVolume {
		root, err := s.cfg.volumeRoot()
		if err != nil {
			return "", fmt.Errorf("gvx: locate the volume directory: %w", err)
		}
		dir := filepath.Join(root, m.VolumeName)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("gvx: create volume %q: %w", m.VolumeName, err)
		}
		return dir, nil
	}
	dir, err := filepath.Abs(m.HostPath)
	if err != nil {
		return "", fmt.Errorf("gvx: resolve bind source %q: %w", m.HostPath, err)
	}
	if m.CreateHostPathIfMissing {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("gvx: create bind source %q: %w", dir, err)
		}
	}
	return dir, nil
}

// sortMountsByDepth orders mounts by increasing guest path depth. A mount
// then never hides the mount point of a deeper mount. Mounts of equal depth
// keep their order.
func sortMountsByDepth(mounts []sandboxMount) {
	sort.SliceStable(mounts, func(i, j int) bool {
		return strings.Count(mounts[i].GuestPath, "/") < strings.Count(mounts[j].GuestPath, "/")
	})
}

// hostMounts lists the host directories that the lockdown must allow.
func (s *Sandbox) hostMounts() []hostlockdown.HostMount {
	var list []hostlockdown.HostMount
	for _, m := range s.mounts {
		if m.Kind != MountTmpfs {
			list = append(list, hostlockdown.HostMount{Path: m.hostPath, ReadOnly: m.ReadOnly})
		}
	}
	return list
}

// closeMounts closes every hostfs workspace once.
func (s *Sandbox) closeMounts() error {
	var errs []error
	for _, ws := range s.workspaces {
		if err := ws.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.workspaces = nil
	s.mounts = nil
	s.workspace = nil
	return errors.Join(errs...)
}
