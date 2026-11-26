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
	"runtime"
	"sort"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

// MountKind selects the backing store of a Mount.
type MountKind string

const (
	// MountBind mounts a host directory or one host regular file through
	// hostfs.
	MountBind MountKind = "bind"
	// MountVolume mounts a volume. The default driver is ext4lite, which
	// stores the volume in one image file: below the gvx cache directory for a
	// named volume, or at Mount.ImagePath.
	MountVolume MountKind = "volume"
	// MountTmpfs mounts a memory-backed tmpfs.
	MountTmpfs MountKind = "tmpfs"
	// MountOverlay mounts a copy-on-write overlay filesystem over an immutable
	// read-only ext4lite base volume with either a persistent ext4lite upper
	// volume or an ephemeral tmpfs upper layer.
	MountOverlay MountKind = "overlay"
	// MountRPCFS identifies a client-served rpcfs proxy mount recorded in a
	// checkpoint manifest.
	MountRPCFS MountKind = "rpcfs"
)

// MountDriver selects the filesystem of a volume mount.
type MountDriver string

const (
	// DriverExt4lite stores the volume in one ext4 image file, <name>.ext4. The
	// sandbox opens the file before the host lockdown. It needs no host
	// directory access afterward. It is the default.
	DriverExt4lite MountDriver = "ext4lite"
	// DriverHostfs stores the volume as a host directory and mounts it through
	// hostfs. It needs a host directory handle that stays open.
	DriverHostfs MountDriver = "hostfs"
)

// Mount describes one extra guest mount. New opens the host directory or the
// host file of a bind mount, or the image of a volume mount, before the host
// lockdown.
type Mount struct {
	// Kind selects the backing store.
	Kind MountKind

	// HostPath is the host directory or the host regular file of a bind
	// mount. A relative path is relative to the working directory of the host
	// process. A file mount exposes only that file: the guest mount point is
	// an empty regular file, and the parent directory and the sibling files
	// stay out of reach of the guest.
	HostPath string

	// VolumeName names a volume. It matches [a-zA-Z0-9][a-zA-Z0-9_.-]*.
	VolumeName string

	// ImagePath is the host path of the image file of an ext4lite volume. A
	// volume mount sets either VolumeName or ImagePath. A relative path is
	// relative to the working directory of the host process. New creates a
	// missing image file, but not its directory. A read-only mount never
	// creates the file.
	ImagePath string

	// UpperVolumeName names the optional persistent writable ext4lite upper
	// volume of a MountOverlay mount. When both UpperVolumeName and
	// UpperImagePath are empty, MountOverlay uses an ephemeral tmpfs upper layer.
	UpperVolumeName string

	// UpperImagePath is the host path of the optional persistent writable
	// ext4lite upper image file of a MountOverlay mount.
	UpperImagePath string

	// Driver selects the filesystem of a volume mount. The zero value selects
	// ext4lite, except for a volume that exists only as a hostfs directory
	// from an older release. That volume keeps using hostfs.
	Driver MountDriver

	// GuestPath is the absolute, clean mount point in the guest. It is not "/".
	// It is not /proc, /sys, or /dev, and it is not below them, except below
	// /dev/shm.
	GuestPath string

	// ReadOnly mounts the guest path in read-only mode. A read-only ext4lite
	// volume opens its image read-only and fails when the image needs repair.
	ReadOnly bool

	// TmpfsSizeBytes limits a tmpfs mount. Zero selects the default limit of
	// the Sentry tmpfs. A bind or volume mount must leave it zero.
	TmpfsSizeBytes int64

	// SizeBytes caps the image in bytes. Zero preserves the existing limit.
	SizeBytes int64

	// Ephemeral selects a new private image for this sandbox run.
	Ephemeral bool

	// CreateHostPathIfMissing creates the host directory of a bind mount when
	// the path does not exist. New creates it before the host lockdown.
	// Without it, a missing path is an error. It never creates a file, and it
	// leaves an existing file or directory as it is. It does not create MetaDir.
	CreateHostPathIfMissing bool

	// MetaDir optionally stores hostfs .gvx_meta, .gvx_meta.lock, and staging
	// files in an existing host directory outside the mounted workspace root.
	// Valid only for directory bind mounts and DriverHostfs volumes. When empty
	// or resolving to the mounted host directory itself, metadata lives in the
	// workspace root. MetaDir must already exist as a directory and cannot be a
	// filesystem root or overlap any mounted host path or another MetaDir.
	// Multiple mounts of the same host directory (for example RO and RW) may
	// share the same MetaDir; concurrent sandboxes sharing metadata for one
	// host directory must supply the same MetaDir.
	MetaDir string
}

type cappedVolumeBinding struct {
	guestPath string
	volume    *ext4lite.Volume
	maxBytes  int64
}

// workspaceGuestPath is the mount point of Config.WorkspacePath.
const workspaceGuestPath = "/workspace"

// rootVolumeUniqueID identifies the internal ext4lite upper layer of the
// container root filesystem in CtxRestoreVolumeMap. User mounts cannot use "/",
// so it never collides with Mount.GuestPath.
const rootVolumeUniqueID = "/"

func overlayLowerUniqueID(guestPath string) string {
	return "overlay-lower:" + guestPath
}

func overlayUpperUniqueID(guestPath string) string {
	return "overlay-upper:" + guestPath
}

func (m Mount) hasOverlayUpper() bool {
	return m.UpperVolumeName != "" || m.UpperImagePath != ""
}

func (m Mount) overlayUpperMount() Mount {
	return Mount{
		Kind:       MountVolume,
		Driver:     DriverExt4lite,
		VolumeName: m.UpperVolumeName,
		ImagePath:  m.UpperImagePath,
	}
}

// volumeNamePattern is the set of valid volume names.
var volumeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// reservedGuestDirs are the guest directories that the kernel mounts itself.
var reservedGuestDirs = []string{"/proc", "/sys", "/dev"}

// ParseVolume parses the value of a -v flag: src:dst[:ro|rw]. A source without
// a path separator that is not absolute names a volume. Any other source is a
// host path: a directory, which New creates when it is missing, or an
// existing regular file. A Windows drive letter in the source is part of the
// source: C:\data:/data:ro.
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

// isHostPathSource reports whether a volume source names a host path.
func isHostPathSource(src string) bool {
	return strings.ContainsAny(src, `/\`) || filepath.IsAbs(src) || hasDrivePrefix(src)
}

// ParseMount parses the value of a --mount flag. The keys are type (bind,
// volume, tmpfs, or overlay; volume when absent), src or source, dst,
// destination, or target, upper, readonly or ro, size, ephemeral, tmpfs-size,
// and driver. A bind source must already exist. A volume or overlay source
// with a path separator sets ImagePath; any other volume or overlay source is
// a volume name.
func ParseMount(spec string) (Mount, error) {
	fields, err := csv.NewReader(strings.NewReader(spec)).Read()
	if err != nil {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, err)
	}
	var (
		kind          = MountVolume
		src, dst      string
		hasSrc        bool
		upper         string
		hasUpper      bool
		tmpfsSize     string
		volSize       string
		hasVolSize    bool
		ephemeral     bool
		seenEphemeral bool
		driver        string
		readOnly      bool
	)
	for _, field := range fields {
		key, value, hasValue := strings.Cut(field, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		switch key {
		case "type":
			kind = MountKind(strings.ToLower(strings.TrimSpace(value)))
		case "src", "source":
			hasSrc = true
			src = value
		case "dst", "destination", "target":
			dst = value
		case "upper":
			hasUpper = true
			upper = value
		case "readonly", "ro":
			readOnly = true
			if hasValue {
				if readOnly, err = strconv.ParseBool(strings.TrimSpace(value)); err != nil {
					return Mount{}, fmt.Errorf("gvx: invalid mount %q: bad value for %s: %w", spec, key, err)
				}
			}
		case "size":
			if hasVolSize {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: duplicate size option", spec)
			}
			if !hasValue || strings.TrimSpace(value) == "" {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: size requires a value", spec)
			}
			hasVolSize = true
			volSize = value
		case "ephemeral":
			if seenEphemeral {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: duplicate ephemeral option", spec)
			}
			if hasValue {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: ephemeral takes no value", spec)
			}
			seenEphemeral = true
			ephemeral = true
		case "tmpfs-size":
			tmpfsSize = value
		case "driver":
			driver = strings.ToLower(strings.TrimSpace(value))
		default:
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: unsupported key %q", spec, key)
		}
	}
	if dst == "" {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: dst is required", spec)
	}
	switch MountDriver(driver) {
	case "", DriverExt4lite, DriverHostfs:
	default:
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: unsupported driver %q (use ext4lite or hostfs)", spec, driver)
	}
	if driver != "" && kind != MountVolume && !(kind == MountOverlay && MountDriver(driver) == DriverExt4lite) {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: driver=%s is unsupported for type=%s", spec, driver, kind)
	}
	if hasUpper && kind != MountOverlay {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: upper needs type=overlay", spec)
	}
	if hasVolSize && kind != MountVolume {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: size needs type=volume", spec)
	}
	if ephemeral && kind != MountVolume {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: ephemeral needs type=volume", spec)
	}
	if (hasVolSize || ephemeral) && MountDriver(driver) == DriverHostfs {
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: size and ephemeral require driver=ext4lite", spec)
	}
	m := Mount{Kind: kind, GuestPath: dst, ReadOnly: readOnly, Driver: MountDriver(driver), Ephemeral: ephemeral}
	if hasVolSize {
		sz, sizeErr := parseVolumeSize(volSize)
		if sizeErr != nil {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, sizeErr)
		}
		m.SizeBytes = sz
	}
	switch kind {
	case MountBind, MountVolume:
		if tmpfsSize != "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: tmpfs-size needs type=tmpfs or type=overlay", spec)
		}
		if kind == MountBind {
			if src == "" {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: src is required for type=%s", spec, kind)
			}
			m.HostPath = src
			return m, nil
		}
		if ephemeral {
			if hasSrc || src != "" {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: ephemeral cannot be combined with src", spec)
			}
			if readOnly {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: ephemeral cannot be combined with readonly", spec)
			}
			return m, nil
		}
		if src == "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: src is required for type=%s", spec, kind)
		}
		if isHostPathSource(src) {
			if m.Driver == DriverHostfs {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: driver=hostfs needs a volume name; use type=bind for a host directory", spec)
			}
			m.ImagePath = src
			return m, nil
		}
		if !volumeNamePattern.MatchString(src) {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: invalid volume name %q", spec, src)
		}
		m.VolumeName = src
	case MountOverlay:
		if err := validateGuestPath(dst); err != nil {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, err)
		}
		if src == "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: src is required for type=overlay", spec)
		}
		if isHostPathSource(src) {
			if strings.HasSuffix(src, "/") || strings.HasSuffix(src, `\`) {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: lower image path %q must name a file", spec, src)
			}
			m.ImagePath = src
		} else {
			if !volumeNamePattern.MatchString(src) {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: invalid volume name %q", spec, src)
			}
			m.VolumeName = src
		}
		if hasUpper {
			if upper == "" {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: upper must not be empty", spec)
			}
			if readOnly {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: readonly cannot be combined with upper", spec)
			}
			if tmpfsSize != "" {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: tmpfs-size cannot be combined with upper", spec)
			}
			if isHostPathSource(upper) {
				if strings.HasSuffix(upper, "/") || strings.HasSuffix(upper, `\`) {
					return Mount{}, fmt.Errorf("gvx: invalid mount %q: upper image path %q must name a file", spec, upper)
				}
				m.UpperImagePath = upper
			} else {
				if !volumeNamePattern.MatchString(upper) {
					return Mount{}, fmt.Errorf("gvx: invalid mount %q: invalid upper volume name %q", spec, upper)
				}
				m.UpperVolumeName = upper
			}
			if (m.VolumeName != "" && m.VolumeName == m.UpperVolumeName) ||
				(m.ImagePath != "" && m.UpperImagePath != "" && filepath.Clean(m.ImagePath) == filepath.Clean(m.UpperImagePath)) {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: overlay lower and upper volumes must differ", spec)
			}
		} else if tmpfsSize != "" {
			if m.TmpfsSizeBytes, err = parseTmpfsSize(tmpfsSize); err != nil {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, err)
			}
		}
	case MountTmpfs:
		if src != "" {
			return Mount{}, fmt.Errorf("gvx: invalid mount %q: type=tmpfs takes no src", spec)
		}
		if tmpfsSize != "" {
			if m.TmpfsSizeBytes, err = parseTmpfsSize(tmpfsSize); err != nil {
				return Mount{}, fmt.Errorf("gvx: invalid mount %q: %w", spec, err)
			}
		}
	default:
		return Mount{}, fmt.Errorf("gvx: invalid mount %q: unsupported type %q (use bind, volume, tmpfs, or overlay)", spec, kind)
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

// parseVolumeSize parses an ext4lite volume size limit with an optional binary
// unit suffix (b, k, kb, kib, m, mb, mib, g, gb, gib, t, tb, or tib) and
// validates that it falls in [16 MiB, 64 TiB] as an exact 16 MiB multiple.
func parseVolumeSize(s string) (int64, error) {
	raw := strings.ToLower(strings.TrimSpace(s))
	if raw == "" {
		return 0, errors.New("volume size must not be empty")
	}
	split := strings.IndexFunc(raw, func(r rune) bool { return r < '0' || r > '9' })
	num, unit := raw, ""
	if split >= 0 {
		num, unit = raw[:split], raw[split:]
	}
	var multiplier int64
	switch unit {
	case "", "b":
		multiplier = 1
	case "k", "kb", "kib":
		multiplier = 1 << 10
	case "m", "mb", "mib":
		multiplier = 1 << 20
	case "g", "gb", "gib":
		multiplier = 1 << 30
	case "t", "tb", "tib":
		multiplier = 1 << 40
	default:
		return 0, fmt.Errorf("unknown unit %q in volume size %q (use b, k, m, g, or t)", unit, s)
	}
	if num == "" {
		return 0, fmt.Errorf("invalid volume size %q", s)
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("volume size %q must be a positive integer", s)
	}
	if n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("volume size %q is too large", s)
	}
	total := n * multiplier
	if err := ext4lite.ValidateMaxBytes(total); err != nil {
		return 0, err
	}
	return total, nil
}

// validateMounts rejects a bad Mounts entry, a duplicate guest path, and a
// mount at /workspace together with WorkspacePath. Every rejection wraps
// ErrInvalidConfig.
func (c *Config) validateMounts() error {
	guestPaths := make(map[string]struct{}, len(c.Mounts)+1)
	if c.WorkspaceMetaDir != "" && c.WorkspacePath == "" {
		return fmt.Errorf("%w: WorkspaceMetaDir requires WorkspacePath", ErrInvalidConfig)
	}
	if c.WorkspacePath != "" {
		if c.WorkspaceMetaDir != "" {
			if err := validateMetaDir(c.WorkspaceMetaDir); err != nil {
				return fmt.Errorf("%w: WorkspaceMetaDir: %w", ErrInvalidConfig, err)
			}
		}
		guestPaths[workspaceGuestPath] = struct{}{}
	}
	hasCheckpointDir := strings.TrimSpace(c.CheckpointDir) != ""
	for i, m := range c.Mounts {
		if err := m.validate(); err != nil {
			return fmt.Errorf("%w: mount %d (%s): %w", ErrInvalidConfig, i, m.GuestPath, err)
		}
		if hasCheckpointDir && m.Ephemeral {
			return fmt.Errorf("%w: mount %d (%s): CheckpointDir cannot be combined with an ephemeral ext4lite volume: %w", ErrInvalidConfig, i, m.GuestPath, ErrCheckpointEphemeralVolume)
		}
		if _, dup := guestPaths[m.GuestPath]; dup {
			if m.GuestPath == workspaceGuestPath && c.WorkspacePath != "" {
				return fmt.Errorf("%w: mount %d at %s conflicts with WorkspacePath", ErrInvalidConfig, i, m.GuestPath)
			}
			return fmt.Errorf("%w: two mounts use the guest path %s", ErrInvalidConfig, m.GuestPath)
		}
		guestPaths[m.GuestPath] = struct{}{}
	}
	for i, sm := range c.ServeMounts {
		if err := validateGuestPath(sm.GuestPath); err != nil {
			return fmt.Errorf("%w: serve mount %d (%s): %w", ErrInvalidConfig, i, sm.GuestPath, err)
		}
		if sm.Client == nil && strings.TrimSpace(sm.HostPath) == "" {
			return fmt.Errorf("%w: serve mount %d (%s) requires HostPath or Client", ErrInvalidConfig, i, sm.GuestPath)
		}
		if _, dup := guestPaths[sm.GuestPath]; dup {
			return fmt.Errorf("%w: two mounts use the guest path %s", ErrInvalidConfig, sm.GuestPath)
		}
		guestPaths[sm.GuestPath] = struct{}{}
	}
	return c.validateVolumeConflicts("")
}

// parseRootVolumeMount converts Config.RootVolume into an ext4lite volume
// descriptor, accepting either a managed volume name or a host image path.
func parseRootVolumeMount(spec string) (Mount, error) {
	if strings.TrimSpace(spec) == "" {
		return Mount{}, fmt.Errorf("%w: root volume must not be empty", ErrInvalidConfig)
	}
	m := Mount{Kind: MountVolume, Driver: DriverExt4lite}
	if isHostPathSource(spec) {
		if strings.HasSuffix(spec, "/") || strings.HasSuffix(spec, `\`) {
			return Mount{}, fmt.Errorf("%w: root volume image path %q must name a file, not a directory", ErrInvalidConfig, spec)
		}
		m.ImagePath = spec
		return m, nil
	}
	if !volumeNamePattern.MatchString(spec) {
		return Mount{}, fmt.Errorf("%w: invalid root volume name %q", ErrInvalidConfig, spec)
	}
	m.VolumeName = spec
	return m, nil
}

// validateRootVolume verifies Config.RootVolume syntax, image-layer presence,
// and compatibility with ReadOnlyRoot.
func (c *Config) validateRootVolume(hasManifestLayers bool) error {
	if c.RootVolume == "" {
		return nil
	}
	m, err := parseRootVolumeMount(c.RootVolume)
	if err != nil {
		return err
	}
	if m.ImagePath != "" {
		if info, statErr := os.Stat(m.ImagePath); statErr == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("%w: root volume %q is not a regular file (mode %s)", ErrInvalidConfig, m.ImagePath, info.Mode().Type())
		}
	}
	if err := c.validateRootVolumeDup(m); err != nil {
		return err
	}
	if c.ReadOnlyRoot {
		return fmt.Errorf("%w: RootVolume cannot be combined with ReadOnlyRoot", ErrInvalidConfig)
	}
	if !hasManifestLayers && c.OCIImage == "" && len(c.OCILayerTars) == 0 {
		return fmt.Errorf("%w: RootVolume requires OCI image layers (set OCIImage or OCILayerTars)", ErrInvalidConfig)
	}
	return nil
}

// validateRootVolumeDup rejects configurations that pass the same ext4lite
// image as both Config.RootVolume and a volume or overlay entry in Config.Mounts.
func (c *Config) validateRootVolumeDup(rootMount Mount) error {
	rootImg, err := c.volumeImagePathWithMigrate(rootMount, false)
	if err != nil {
		return err
	}
	return c.validateVolumeConflicts(rootImg)
}

func (c *Config) validateVolumeConflicts(rootImg string) error {
	rwImages := make(map[string]bool)
	roImages := make(map[string]bool)
	hasROLimit := make(map[string]bool)
	roLimits := make(map[string]int64)
	if rootImg != "" {
		rwImages[rootImg] = true
	}
	checkRW := func(img, label string) error {
		if rwImages[img] || roImages[img] {
			return fmt.Errorf("%w: volume %s is mounted twice", ErrInvalidConfig, label)
		}
		rwImages[img] = true
		return nil
	}
	checkRO := func(img, label string, limit int64) error {
		if rwImages[img] {
			return fmt.Errorf("%w: volume %s is mounted twice", ErrInvalidConfig, label)
		}
		if hasROLimit[img] && roLimits[img] != limit {
			return fmt.Errorf("%w: shared read-only volume %s has conflicting size limits (%d vs %d)", ErrInvalidConfig, label, roLimits[img], limit)
		}
		roImages[img] = true
		hasROLimit[img] = true
		roLimits[img] = limit
		return nil
	}

	for _, m := range c.Mounts {
		switch m.Kind {
		case MountVolume:
			if m.Ephemeral {
				continue
			}
			driver, err := c.resolveVolumeDriverWithMigrate(m, false)
			if err != nil {
				continue
			}
			if driver != DriverExt4lite {
				if m.SizeBytes > 0 {
					return fmt.Errorf("%w: volume %s uses driver %q, which does not support size", ErrInvalidConfig, m.volumeLabel(), driver)
				}
				continue
			}
			if m.MetaDir != "" {
				return fmt.Errorf("%w: volume %s uses driver %q, which does not support MetaDir", ErrInvalidConfig, m.volumeLabel(), driver)
			}
			img, err := c.volumeImagePathWithMigrate(m, false)
			if err != nil {
				continue
			}
			if m.ReadOnly {
				if err := checkRO(img, m.volumeLabel(), m.SizeBytes); err != nil {
					return err
				}
			} else {
				if err := checkRW(img, m.volumeLabel()); err != nil {
					return err
				}
			}
		case MountOverlay:
			lowerImg, err := c.volumeImagePathWithMigrate(m, false)
			if err != nil {
				continue
			}
			if m.hasOverlayUpper() {
				upperMount := m.overlayUpperMount()
				upperImg, err := c.volumeImagePathWithMigrate(upperMount, false)
				if err != nil {
					continue
				}
				if lowerImg == upperImg {
					return fmt.Errorf("%w: overlay volume %s is mounted twice as lower and upper", ErrInvalidConfig, upperMount.volumeLabel())
				}
				if err := checkRW(upperImg, upperMount.volumeLabel()); err != nil {
					return err
				}
			}
			if err := checkRO(lowerImg, m.volumeLabel(), 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate checks one mount. The caller adds the context to the error.
func (m Mount) validate() error {
	if err := validateGuestPath(m.GuestPath); err != nil {
		return err
	}
	if m.TmpfsSizeBytes < 0 || (m.TmpfsSizeBytes > 0 && m.Kind != MountTmpfs && (m.Kind != MountOverlay || m.hasOverlayUpper())) {
		return errors.New("TmpfsSizeBytes must be zero or positive and applies to tmpfs or ephemeral overlay mounts only")
	}
	if m.SizeBytes < 0 {
		return errors.New("SizeBytes must be zero or positive")
	}
	if m.SizeBytes > 0 {
		if m.Kind != MountVolume {
			return errors.New("SizeBytes applies to volume mounts only")
		}
		if m.Driver == DriverHostfs {
			return errors.New("SizeBytes requires the ext4lite volume driver")
		}
		if err := ext4lite.ValidateMaxBytes(m.SizeBytes); err != nil {
			return err
		}
	}
	if m.Ephemeral {
		if m.Kind != MountVolume {
			return errors.New("Ephemeral applies to volume mounts only")
		}
		if m.Driver == DriverHostfs {
			return errors.New("Ephemeral requires the ext4lite volume driver")
		}
		if m.HostPath != "" || m.VolumeName != "" || m.ImagePath != "" {
			return errors.New("an ephemeral volume mount takes no HostPath, VolumeName, or ImagePath")
		}
		if m.ReadOnly {
			return errors.New("an ephemeral volume mount cannot be read-only")
		}
	}
	if m.CreateHostPathIfMissing && m.Kind != MountBind {
		return errors.New("CreateHostPathIfMissing applies to bind mounts only")
	}
	if m.MetaDir != "" {
		switch m.Kind {
		case MountBind:
		case MountVolume:
			if m.Ephemeral || m.ImagePath != "" || (m.Driver != "" && m.Driver != DriverHostfs) {
				return errors.New("MetaDir applies to directory bind mounts and hostfs volumes only")
			}
		default:
			return errors.New("MetaDir applies to directory bind mounts and hostfs volumes only")
		}
		if err := validateMetaDir(m.MetaDir); err != nil {
			return err
		}
	}
	if m.hasOverlayUpper() && m.Kind != MountOverlay {
		return errors.New("UpperVolumeName and UpperImagePath apply to overlay mounts only")
	}
	if m.Driver != "" && m.Kind != MountVolume && !(m.Kind == MountOverlay && m.Driver == DriverExt4lite) {
		return errors.New("Driver applies to volume mounts only")
	}
	switch m.Kind {
	case MountBind:
		if m.VolumeName != "" || m.ImagePath != "" {
			return errors.New("a bind mount takes no VolumeName or ImagePath")
		}
		return m.validateBindSource()
	case MountVolume:
		if m.HostPath != "" {
			return errors.New("a volume mount takes no HostPath")
		}
		if m.Ephemeral {
			return nil
		}
		if m.ImagePath != "" {
			if m.VolumeName != "" {
				return errors.New("a volume mount takes VolumeName or ImagePath, not both")
			}
			if m.Driver != "" && m.Driver != DriverExt4lite {
				return fmt.Errorf("a volume with an ImagePath needs the ext4lite driver, not %q", m.Driver)
			}
			return nil
		}
		if !volumeNamePattern.MatchString(m.VolumeName) {
			return fmt.Errorf("invalid volume name %q", m.VolumeName)
		}
		switch m.Driver {
		case "", DriverExt4lite, DriverHostfs:
		default:
			return fmt.Errorf("unsupported volume driver %q (use ext4lite or hostfs)", m.Driver)
		}
	case MountOverlay:
		if m.HostPath != "" {
			return errors.New("an overlay mount takes no HostPath")
		}
		if m.ImagePath != "" {
			if m.VolumeName != "" {
				return errors.New("an overlay mount takes VolumeName or ImagePath for lower base, not both")
			}
			if strings.HasSuffix(m.ImagePath, "/") || strings.HasSuffix(m.ImagePath, `\`) {
				return fmt.Errorf("overlay lower image path %q must name a file", m.ImagePath)
			}
		} else if !volumeNamePattern.MatchString(m.VolumeName) {
			return fmt.Errorf("invalid volume name %q", m.VolumeName)
		}
		if m.UpperImagePath != "" && m.UpperVolumeName != "" {
			return errors.New("an overlay mount takes UpperVolumeName or UpperImagePath, not both")
		}
		if m.hasOverlayUpper() {
			if m.ReadOnly {
				return errors.New("a read-only overlay mount cannot set an upper volume")
			}
			if m.UpperImagePath != "" {
				if strings.HasSuffix(m.UpperImagePath, "/") || strings.HasSuffix(m.UpperImagePath, `\`) {
					return fmt.Errorf("overlay upper image path %q must name a file", m.UpperImagePath)
				}
			} else if !volumeNamePattern.MatchString(m.UpperVolumeName) {
				return fmt.Errorf("invalid upper volume name %q", m.UpperVolumeName)
			}
			if (m.VolumeName != "" && m.VolumeName == m.UpperVolumeName) ||
				(m.ImagePath != "" && m.UpperImagePath != "" && filepath.Clean(m.ImagePath) == filepath.Clean(m.UpperImagePath)) {
				return errors.New("overlay lower and upper volumes must differ")
			}
		}
	case MountTmpfs:
		if m.HostPath != "" || m.VolumeName != "" || m.ImagePath != "" {
			return errors.New("a tmpfs mount takes no HostPath, VolumeName, or ImagePath")
		}
	default:
		return fmt.Errorf("unsupported mount kind %q", m.Kind)
	}
	return nil
}

// validateBindSource requires an existing directory or an existing regular
// file. A missing path is valid when CreateHostPathIfMissing is set. That
// option creates a directory only.
func (m Mount) validateBindSource() error {
	if m.HostPath == "" {
		return errors.New("a bind mount needs HostPath")
	}
	kind, err := classifyHostPath(m.HostPath)
	switch {
	case err != nil:
		return fmt.Errorf("bind source %q: %w", m.HostPath, err)
	case kind == hostPathMissing && !m.CreateHostPathIfMissing:
		return fmt.Errorf("bind source %q does not exist", m.HostPath)
	case kind == hostPathFile && m.MetaDir != "":
		return fmt.Errorf("bind source %q is a regular file: MetaDir applies to directory mounts only", m.HostPath)
	}
	return nil
}

func validateMetaDir(metaDir string) error {
	abs, err := filepath.Abs(metaDir)
	if err != nil {
		return fmt.Errorf("resolve MetaDir %q: %w", metaDir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("MetaDir %q: %w", metaDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("MetaDir %q must be a directory", metaDir)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("resolve symlinks for MetaDir %q: %w", metaDir, err)
	}
	real = filepath.Clean(real)
	if filepath.Dir(real) == real {
		return fmt.Errorf("MetaDir %q must not be a filesystem root", metaDir)
	}
	return nil
}

func stripWindowsExtendedPrefix(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	if rest, ok := strings.CutPrefix(p, `\\?\`); ok {
		return rest
	}
	return p
}

func canonicalHostPath(p string) string {
	resolved := stripWindowsExtendedPrefix(resolveSymlinkPrefix(filepath.Clean(p)))
	if runtime.GOOS == "windows" {
		return strings.ToLower(resolved)
	}
	return resolved
}

func sameHostPath(a, b string) bool {
	if ai, errA := os.Stat(a); errA == nil {
		if bi, errB := os.Stat(b); errB == nil {
			return os.SameFile(ai, bi)
		}
	}
	return canonicalHostPath(a) == canonicalHostPath(b)
}

// hostPathContainsStrict reports whether child lies strictly beneath parent,
// combining physical filesystem identity (os.SameFile ancestor walk) with
// lexical containment for not-yet-created path tails.
func hostPathContainsStrict(parent, child string) bool {
	if sameHostPath(parent, child) {
		return false
	}
	resolvedParent := resolveSymlinkPrefix(filepath.Clean(parent))
	resolvedChild := resolveSymlinkPrefix(filepath.Clean(child))
	if parentInfo, err := os.Stat(resolvedParent); err == nil {
		cur := resolvedChild
		for {
			next := filepath.Dir(cur)
			if next == cur {
				break
			}
			cur = next
			if curInfo, serr := os.Stat(cur); serr == nil && os.SameFile(parentInfo, curInfo) {
				return true
			}
		}
	}
	p := canonicalHostPath(resolvedParent)
	c := canonicalHostPath(resolvedChild)
	if p == c {
		return false
	}
	rel, err := filepath.Rel(p, c)
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// hostPathKind is the type of a host path that a bind mount names.
type hostPathKind int

const (
	hostPathMissing hostPathKind = iota
	hostPathDir
	hostPathFile
)

// classifyHostPath reports whether p is a directory, a regular file, or
// missing. It follows symbolic links. It returns an error for any other file
// type, such as a socket or a device, and for a failed stat.
func classifyHostPath(p string) (hostPathKind, error) {
	info, err := os.Stat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return hostPathMissing, nil
	case err != nil:
		return hostPathMissing, err
	case info.IsDir():
		return hostPathDir, nil
	case info.Mode().IsRegular():
		return hostPathFile, nil
	}
	return hostPathMissing, fmt.Errorf("is neither a directory nor a regular file (mode %s)", info.Mode().Type())
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

// hasHostDirs reports whether the configuration asks for a host path: a
// directory or a file. A volume asks for one only when its driver is hostfs. A
// volume without a driver uses ext4lite, unless it falls back to an older
// hostfs directory. The Sandbox knows that case only when it has opened the
// mounts, so the Linux seccomp filter uses Sandbox.usesHostDirs.
func (c Config) hasHostDirs() bool {
	if c.WorkspacePath != "" {
		return true
	}
	for _, m := range c.Mounts {
		switch {
		case m.Kind == MountTmpfs:
		case m.Kind == MountOverlay:
		case m.Kind == MountVolume && m.Driver != DriverHostfs:
		default:
			return true
		}
	}
	return false
}

// sandboxMount is a Mount that New has prepared. A bind mount or a hostfs
// volume holds its absolute host path and its open hostfs workspace. The
// host path is a regular file when hostFile is set, and a directory
// otherwise. An ext4lite volume holds its open volume.
type sandboxMount struct {
	Mount
	hostPath         string
	hostFile         bool
	backingReadOnly  bool
	dynamic          bool
	workspace        *hostfs.Workspace
	volume           *ext4lite.Volume
	upperVolume      *ext4lite.Volume
	hasSandboxExt    bool
	sandboxExtHandle int64
}

// IssueBindAttachToken issues a host sandbox file extension token (macOS
// Seatbelt) for hostPath so a locked sandbox with AllowBindAttach enabled can
// consume it when receiving the directory descriptor over SCM_RIGHTS. Outside
// macOS it returns an empty string and nil error.
func IssueBindAttachToken(hostPath string, readOnly bool) (string, error) {
	return hostlockdown.IssueFileExtension(hostPath, readOnly)
}

// mountList returns every guest mount: the WorkspacePath mount first, then
// Mounts in order.
func (c Config) mountList() []Mount {
	list := make([]Mount, 0, len(c.Mounts)+1)
	if c.WorkspacePath != "" {
		list = append(list, Mount{
			Kind:      MountBind,
			HostPath:  c.WorkspacePath,
			GuestPath: workspaceGuestPath,
			ReadOnly:  c.WorkspaceReadOnly,
			MetaDir:   c.WorkspaceMetaDir,
		})
	}
	return append(list, c.Mounts...)
}

// workspaceKey identifies a hostfs workspace. A file mount and a directory
// mount of its parent are different workspaces.
type workspaceKey struct {
	path     string
	file     bool
	readOnly bool
}

// newWorkspaceKey returns the key of a host path. It resolves symbolic links
// when it can, so two names of one path share a key.
func newWorkspaceKey(hostPath string, file, readOnly bool) workspaceKey {
	if resolved, err := filepath.EvalSymlinks(hostPath); err == nil {
		hostPath = resolved
	}
	return workspaceKey{path: hostPath, file: file, readOnly: readOnly}
}

// openMounts prepares the host paths, opens one hostfs workspace for each
// bind mount and each hostfs volume, opens the image of each ext4lite volume,
// and records the mounts in the order that the guest mounts them. A path that
// two mounts share with the same access and the same kind (directory or
// file) shares one workspace, so two flush loops never write the same
// metadata file. A host directory that lies inside another mounted host
// directory gets its own workspace and its own table. openMounts must run
// before the host lockdown.
func (s *Sandbox) openMounts() error {
	return s.openMountsWithMode(false)
}

// openMountsForRestore opens every mount before the host lockdown in restore
// mode: hostfs workspaces keep unlinked .gvx_tmp_* backing files until
// CompleteRestore claims them, and ext4lite volumes defer orphan cleanup until
// CompleteRestore rebinds open orphan inodes.
func (s *Sandbox) openMountsForRestore() error {
	return s.openMountsWithMode(true)
}

func checkNoLegacyHostfsVolume(m Mount, image string) error {
	if m.ImagePath != "" {
		return nil
	}
	if _, statErr := os.Stat(image); errors.Is(statErr, os.ErrNotExist) {
		legacyDir := filepath.Join(filepath.Dir(image), m.VolumeName)
		if info, dirErr := os.Stat(legacyDir); dirErr == nil && info.IsDir() {
			return fmt.Errorf("%w: volume %q already exists with driver %q", ErrInvalidConfig, m.VolumeName, DriverHostfs)
		}
	}
	return nil
}

func (s *Sandbox) resolveHostPathCandidate(m Mount) (string, bool, error) {
	if m.Kind == MountVolume {
		root, err := s.cfg.volumeRoot()
		if err != nil {
			return "", false, fmt.Errorf("gvx: locate the volume directory: %w", err)
		}
		return filepath.Join(root, m.VolumeName), false, nil
	}
	abs, err := filepath.Abs(m.HostPath)
	if err != nil {
		return "", false, fmt.Errorf("gvx: resolve bind source %q: %w", m.HostPath, err)
	}
	kind, err := classifyHostPath(abs)
	if err != nil {
		return "", false, fmt.Errorf("gvx: bind source %q: %w", abs, err)
	}
	if kind == hostPathFile {
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return "", false, fmt.Errorf("gvx: resolve bind source %q: %w", abs, err)
		}
		return resolved, true, nil
	}
	return abs, false, nil
}

// validateHostMountPlacements verifies all hostfs mounts and their MetaDir
// placements before any missing host directory is created on disk. It returns
// the normalized per-mount MetaDir (empty when default/same-dir) indexed by
// mountList position.
func (s *Sandbox) validateHostMountPlacements(mounts []Mount) (map[int]string, error) {
	type hostMountPlacement struct {
		guestPath string
		hostPath  string
		isFile    bool
		metaPath  string // resolved external MetaDir, or "" when in-workspace
		effMeta   string // metaPath when non-empty, else hostPath
	}
	var placements []hostMountPlacement
	normMeta := make(map[int]string)

	for i, m := range mounts {
		switch {
		case m.Kind == MountTmpfs, m.Kind == MountOverlay:
			continue
		case m.Kind == MountVolume:
			driver, err := s.cfg.resolveVolumeDriverWithMigrate(m, false)
			if err != nil {
				return nil, err
			}
			if (m.SizeBytes > 0 || m.Ephemeral) && driver != DriverExt4lite {
				return nil, fmt.Errorf("gvx: volume %s uses driver %q, which does not support size or ephemeral: %w", m.volumeLabel(), driver, ErrInvalidConfig)
			}
			if m.MetaDir != "" && driver != DriverHostfs {
				return nil, fmt.Errorf("gvx: volume %s uses driver %q, which does not support MetaDir: %w", m.volumeLabel(), driver, ErrInvalidConfig)
			}
			if driver == DriverExt4lite {
				continue
			}
		}

		hostPath, isFile, err := s.resolveHostPathCandidate(m)
		if err != nil {
			return nil, err
		}
		if isFile && m.GuestPath == workspaceGuestPath && s.cfg.WorkspacePath != "" {
			return nil, fmt.Errorf("gvx: WorkspacePath %q is a file: it must be a directory: %w", hostPath, ErrInvalidConfig)
		}
		if isFile && m.MetaDir != "" {
			return nil, fmt.Errorf("gvx: mount %s is a regular file and does not support MetaDir: %w", m.GuestPath, ErrInvalidConfig)
		}

		metaPath := ""
		if m.MetaDir != "" {
			if err := validateMetaDir(m.MetaDir); err != nil {
				return nil, fmt.Errorf("gvx: mount %s: %w: %w", m.GuestPath, err, ErrInvalidConfig)
			}
			absMeta, err := filepath.Abs(m.MetaDir)
			if err != nil {
				return nil, fmt.Errorf("gvx: mount %s: resolve MetaDir %q: %w: %w", m.GuestPath, m.MetaDir, err, ErrInvalidConfig)
			}
			candMeta := resolveSymlinkPrefix(filepath.Clean(absMeta))
			if !sameHostPath(hostPath, candMeta) {
				if hostPathContainsStrict(hostPath, candMeta) {
					return nil, fmt.Errorf("gvx: mount %s: MetaDir %q must not lie inside host path %q: %w", m.GuestPath, m.MetaDir, hostPath, ErrInvalidConfig)
				}
				if hostPathContainsStrict(candMeta, hostPath) {
					return nil, fmt.Errorf("gvx: mount %s: MetaDir %q must not be an ancestor of host path %q: %w", m.GuestPath, m.MetaDir, hostPath, ErrInvalidConfig)
				}
				metaPath = candMeta
			}
		}
		effMeta := hostPath
		if metaPath != "" {
			effMeta = metaPath
		}

		for _, prev := range placements {
			if !isFile && !prev.isFile {
				sameHost := sameHostPath(hostPath, prev.hostPath)
				sameEff := sameHostPath(effMeta, prev.effMeta)
				if sameHost && !sameEff {
					return nil, fmt.Errorf("gvx: mounts %s and %s share host path %q with conflicting MetaDir settings: %w", prev.guestPath, m.GuestPath, hostPath, ErrInvalidConfig)
				}
				if !sameHost && sameEff {
					return nil, fmt.Errorf("gvx: mounts %s and %s target distinct host directories with the same metadata directory: %w", prev.guestPath, m.GuestPath, ErrInvalidConfig)
				}
			}
			if metaPath != "" {
				if sameHostPath(metaPath, prev.hostPath) || hostPathContainsStrict(prev.hostPath, metaPath) || hostPathContainsStrict(metaPath, prev.hostPath) {
					return nil, fmt.Errorf("gvx: mount %s MetaDir %q overlaps mount %s host path: %w", m.GuestPath, m.MetaDir, prev.guestPath, ErrInvalidConfig)
				}
				if prev.metaPath != "" && (hostPathContainsStrict(prev.metaPath, metaPath) || hostPathContainsStrict(metaPath, prev.metaPath)) {
					return nil, fmt.Errorf("gvx: mount %s MetaDir %q overlaps mount %s MetaDir: %w", m.GuestPath, m.MetaDir, prev.guestPath, ErrInvalidConfig)
				}
			}
			if prev.metaPath != "" {
				if sameHostPath(prev.metaPath, hostPath) || hostPathContainsStrict(hostPath, prev.metaPath) || hostPathContainsStrict(prev.metaPath, hostPath) {
					return nil, fmt.Errorf("gvx: mount %s host path %q overlaps mount %s MetaDir: %w", m.GuestPath, hostPath, prev.guestPath, ErrInvalidConfig)
				}
			}
		}

		placements = append(placements, hostMountPlacement{
			guestPath: m.GuestPath,
			hostPath:  hostPath,
			isFile:    isFile,
			metaPath:  metaPath,
			effMeta:   effMeta,
		})
		normMeta[i] = metaPath
	}
	return normMeta, nil
}

func (s *Sandbox) openMountsWithMode(forRestore bool) error {
	shared := make(map[workspaceKey]*hostfs.Workspace)
	mountList := s.cfg.mountList()
	normMeta, err := s.validateHostMountPlacements(mountList)
	if err != nil {
		return err
	}
	rwVolumes := make(map[string]bool)
	roVolumes := make(map[string]*ext4lite.Volume)
	hasROLimit := make(map[string]bool)
	roLimits := make(map[string]int64)

	openRW := func(m Mount) (*ext4lite.Volume, string, error) {
		image, err := s.cfg.volumeImagePath(m)
		if err != nil {
			return nil, "", err
		}
		if rwVolumes[image] || roVolumes[image] != nil {
			return nil, "", fmt.Errorf("gvx: volume %s is mounted twice: %w", m.volumeLabel(), ErrInvalidConfig)
		}
		rwVolumes[image] = true
		vol, err := s.openVolumeImageWithMode(m, image, forRestore)
		if err != nil {
			return nil, "", err
		}
		return vol, image, nil
	}
	openRO := func(m Mount) (*ext4lite.Volume, error) {
		m.ReadOnly = true
		image, err := s.cfg.volumeImagePath(m)
		if err != nil {
			return nil, err
		}
		if rwVolumes[image] {
			return nil, fmt.Errorf("gvx: volume %s is mounted twice: %w", m.volumeLabel(), ErrInvalidConfig)
		}
		if hasROLimit[image] && roLimits[image] != m.SizeBytes {
			return nil, fmt.Errorf("gvx: shared read-only volume %s has conflicting size limits (%d vs %d): %w", m.volumeLabel(), roLimits[image], m.SizeBytes, ErrInvalidConfig)
		}
		if vol, ok := roVolumes[image]; ok {
			return vol, nil
		}
		vol, err := s.openVolumeImageWithMode(m, image, false)
		if err != nil {
			return nil, err
		}
		roVolumes[image] = vol
		hasROLimit[image] = true
		roLimits[image] = m.SizeBytes
		s.volumes = append(s.volumes, vol)
		return vol, nil
	}

	if s.cfg.RootVolume != "" {
		m, err := parseRootVolumeMount(s.cfg.RootVolume)
		if err != nil {
			return err
		}
		image, err := s.cfg.volumeImagePath(m)
		if err != nil {
			return err
		}
		if err := checkNoLegacyHostfsVolume(m, image); err != nil {
			return err
		}
		rwVolumes[image] = true
		vol, err := s.openVolumeImageWithMode(m, image, forRestore)
		if err != nil {
			return err
		}
		s.rootVolume = vol
	}
	for idx, m := range mountList {
		if m.Kind == MountVolume {
			driver, err := s.cfg.resolveVolumeDriver(m)
			if err != nil {
				return err
			}
			if (m.SizeBytes > 0 || m.Ephemeral) && driver != DriverExt4lite {
				return fmt.Errorf("gvx: volume %s uses driver %q, which does not support size or ephemeral: %w", m.volumeLabel(), driver, ErrInvalidConfig)
			}
			if m.MetaDir != "" && driver != DriverHostfs {
				return fmt.Errorf("gvx: volume %s uses driver %q, which does not support MetaDir: %w", m.volumeLabel(), driver, ErrInvalidConfig)
			}
			m.Driver = driver
		}
		sm := sandboxMount{Mount: m}
		switch {
		case m.Kind == MountTmpfs:
			sm.backingReadOnly = false
		case m.Kind == MountOverlay:
			sm.backingReadOnly = m.ReadOnly
			lowerImg, err := s.cfg.volumeImagePath(m)
			if err != nil {
				return err
			}
			if err := checkNoLegacyHostfsVolume(m, lowerImg); err != nil {
				return err
			}
			if m.hasOverlayUpper() {
				upperMount := m.overlayUpperMount()
				upperImg, err := s.cfg.volumeImagePath(upperMount)
				if err != nil {
					return err
				}
				if lowerImg == upperImg {
					return fmt.Errorf("gvx: overlay volume %s is mounted twice: %w", upperMount.volumeLabel(), ErrInvalidConfig)
				}
				if err := checkNoLegacyHostfsVolume(upperMount, upperImg); err != nil {
					return err
				}
				upperVol, _, err := openRW(upperMount)
				if err != nil {
					return err
				}
				s.volumes = append(s.volumes, upperVol)
				sm.upperVolume = upperVol
			}
			lowerMount := m
			lowerMount.SizeBytes = 0
			lowerVol, err := openRO(lowerMount)
			if err != nil {
				return err
			}
			sm.volume = lowerVol
		case m.Kind == MountVolume && m.Driver == DriverExt4lite:
			if m.Ephemeral {
				if forRestore {
					return fmt.Errorf("%w: ephemeral ext4lite volume at %q cannot be restored", ErrInvalidConfig, m.GuestPath)
				}
				s.hasEphemeralVolume = true
				vol, err := s.openEphemeralVolume(m)
				if err != nil {
					return err
				}
				s.volumes = append(s.volumes, vol)
				sm.volume = vol
				sm.backingReadOnly = false
			} else {
				backingRO := m.ReadOnly
				if forRestore && s.restoreBackingRO != nil {
					if ro, ok := s.restoreBackingRO[m.GuestPath]; ok {
						backingRO = ro
					}
				}
				sm.backingReadOnly = backingRO
				openMount := m
				openMount.ReadOnly = backingRO
				if backingRO {
					vol, err := openRO(openMount)
					if err != nil {
						return err
					}
					sm.volume = vol
				} else {
					vol, _, err := openRW(openMount)
					if err != nil {
						return err
					}
					s.volumes = append(s.volumes, vol)
					sm.volume = vol
				}
				if m.SizeBytes > 0 {
					s.cappedVolumes = append(s.cappedVolumes, cappedVolumeBinding{
						guestPath: m.GuestPath,
						volume:    sm.volume,
						maxBytes:  m.SizeBytes,
					})
				}
			}
		default:
			hostPath, isFile, err := s.prepareHostPath(m)
			if err != nil {
				return err
			}
			if isFile && m.GuestPath == workspaceGuestPath && s.cfg.WorkspacePath != "" {
				return fmt.Errorf("gvx: WorkspacePath %q is a file: it must be a directory: %w", hostPath, ErrInvalidConfig)
			}
			if isFile && m.MetaDir != "" {
				return fmt.Errorf("gvx: mount %s is a regular file and does not support MetaDir: %w", m.GuestPath, ErrInvalidConfig)
			}
			metaDir := normMeta[idx]
			sm.hostPath = hostPath
			sm.hostFile = isFile
			key := newWorkspaceKey(hostPath, isFile, m.ReadOnly)
			ws, ok := shared[key]
			if !ok {
				ws, err = hostfs.OpenWorkspaceWithOptions(hostPath, hostfs.OpenOptions{
					ReadOnly:    m.ReadOnly,
					MetaDir:     metaDir,
					RestoreMode: forRestore,
				})
				if err != nil {
					return fmt.Errorf("gvx: open mount %s from %q: %w", m.GuestPath, hostPath, err)
				}
				shared[key] = ws
				s.workspaces = append(s.workspaces, ws)
			}
			sm.workspace = ws
			sm.backingReadOnly = ws.ReadOnly()
		}
		s.mounts = append(s.mounts, sm)
		if m.GuestPath == workspaceGuestPath {
			s.workspace = sm.workspace
		}
	}
	sortMountsByDepth(s.mounts)
	return nil
}

// volumeImagePath returns the absolute host path of the image file of a
// volume. Two mounts of one image get the same path, so openMounts can refuse
// the second one.
func (c Config) volumeImagePath(m Mount) (string, error) {
	return c.volumeImagePathWithMigrate(m, true)
}

func (c Config) volumeImagePathWithMigrate(m Mount, migrate bool) (string, error) {
	if m.ImagePath != "" {
		abs, err := filepath.Abs(m.ImagePath)
		if err != nil {
			return "", fmt.Errorf("gvx: resolve volume image %q: %w", m.ImagePath, err)
		}
		return resolveSymlinkPrefix(abs), nil
	}
	root, err := c.volumeRootWithMigrate(migrate)
	if err != nil {
		return "", fmt.Errorf("gvx: locate the volume directory: %w", err)
	}
	return resolveSymlinkPrefix(filepath.Join(root, m.VolumeName+".ext4")), nil
}

// resolveSymlinkPrefix resolves symlinks along the longest existing prefix of
// p so paths to uncreated and created files match on symlinked temp roots.
func resolveSymlinkPrefix(p string) string {
	var tail []string
	cur := filepath.Clean(p)
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// volumeLabel names a volume mount in messages: the quoted name, or the
// image path.
func (m Mount) volumeLabel() string {
	if m.Ephemeral {
		return fmt.Sprintf("ephemeral volume at %q", m.GuestPath)
	}
	if m.ImagePath != "" {
		return fmt.Sprintf("image %q", m.ImagePath)
	}
	return fmt.Sprintf("%q", m.VolumeName)
}

// resolveVolumeDriver picks the driver of a volume mount. An explicit driver
// wins. Without one, a volume uses ext4lite, unless a hostfs directory of that
// name exists and no image exists. A volume from an older release lives in
// that directory, and the mount must not hide its files.
func (c Config) resolveVolumeDriver(m Mount) (MountDriver, error) {
	return c.resolveVolumeDriverWithMigrate(m, true)
}

func (c Config) resolveVolumeDriverWithMigrate(m Mount, migrate bool) (MountDriver, error) {
	if m.Driver != "" {
		return m.Driver, nil
	}
	if m.Ephemeral || m.ImagePath != "" {
		return DriverExt4lite, nil
	}
	image, err := c.volumeImagePathWithMigrate(m, migrate)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(image); err == nil {
		return DriverExt4lite, nil
	}
	root := filepath.Dir(image)
	if info, err := os.Stat(filepath.Join(root, m.VolumeName)); err == nil && info.IsDir() {
		return DriverHostfs, nil
	}
	return DriverExt4lite, nil
}

// openVolumeImage opens the image file of an ext4lite volume at image and
// creates it when it does not exist. A read-only mount opens the file
// read-only and never creates it. For a named volume, it also creates the
// volume directory. For an ImagePath, the directory must exist.
func (s *Sandbox) openVolumeImage(m Mount, image string) (*ext4lite.Volume, error) {
	return s.openVolumeImageWithMode(m, image, false)
}

func (s *Sandbox) openVolumeImageWithMode(m Mount, image string, forRestore bool) (*ext4lite.Volume, error) {
	if info, err := os.Stat(image); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("gvx: volume %s: %q is not a regular file (mode %s): %w", m.volumeLabel(), image, info.Mode().Type(), ErrInvalidConfig)
	}
	flags := os.O_RDWR | os.O_CREATE
	if m.ReadOnly {
		flags = os.O_RDONLY
	} else if forRestore {
		flags = os.O_RDWR
	} else if m.ImagePath == "" {
		if err := os.MkdirAll(filepath.Dir(image), 0o700); err != nil {
			return nil, fmt.Errorf("gvx: create the volume directory: %w", err)
		}
	}
	f, err := os.OpenFile(image, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("gvx: open volume %s: %w", m.volumeLabel(), err)
	}
	vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{
		ReadOnly:           m.ReadOnly,
		DeferOrphanCleanup: forRestore && !m.ReadOnly,
		MaxBytes:           m.SizeBytes,
	})
	if errors.Is(err, ext4lite.ErrVolumeInUse) {
		return nil, fmt.Errorf("gvx: volume %s is in use by another sandbox: %w", m.volumeLabel(), err)
	}
	if errors.Is(err, ext4lite.ErrInvalidVolumeSize) || errors.Is(err, ext4lite.ErrVolumeExceedsMaxBytes) {
		return nil, fmt.Errorf("gvx: mount volume %s from %q: %w: %w", m.volumeLabel(), image, ErrInvalidConfig, err)
	}
	if err != nil {
		return nil, fmt.Errorf("gvx: mount volume %s from %q: %w", m.volumeLabel(), image, err)
	}
	return vol, nil
}

// prepareHostPath returns the absolute host path of a bind or volume mount
// and whether that path is a regular file. It creates a missing directory
// when the mount asks for it. It never creates or changes a file. A volume
// directory gets mode 0700. The path of a file mount has no symbolic link,
// so hostfs and the lockdown pin the real file.
func (s *Sandbox) prepareHostPath(m Mount) (string, bool, error) {
	if m.Kind == MountVolume {
		root, err := s.cfg.volumeRoot()
		if err != nil {
			return "", false, fmt.Errorf("gvx: locate the volume directory: %w", err)
		}
		dir := filepath.Join(root, m.VolumeName)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", false, fmt.Errorf("gvx: create volume %q: %w", m.VolumeName, err)
		}
		return dir, false, nil
	}
	abs, err := filepath.Abs(m.HostPath)
	if err != nil {
		return "", false, fmt.Errorf("gvx: resolve bind source %q: %w", m.HostPath, err)
	}
	kind, err := classifyHostPath(abs)
	if err != nil {
		return "", false, fmt.Errorf("gvx: bind source %q: %w", abs, err)
	}
	switch kind {
	case hostPathFile:
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return "", false, fmt.Errorf("gvx: resolve bind source %q: %w", abs, err)
		}
		return resolved, true, nil
	case hostPathMissing:
		if m.CreateHostPathIfMissing {
			if err := os.MkdirAll(abs, 0o755); err != nil {
				return "", false, fmt.Errorf("gvx: create bind source %q: %w", abs, err)
			}
		}
	case hostPathDir:
	}
	return abs, false, nil
}

// sortMountsByDepth orders mounts by increasing guest path depth. A mount
// then never hides the mount point of a deeper mount. Mounts of equal depth
// keep their order.
func sortMountsByDepth(mounts []sandboxMount) {
	sort.SliceStable(mounts, func(i, j int) bool {
		return strings.Count(mounts[i].GuestPath, "/") < strings.Count(mounts[j].GuestPath, "/")
	})
}

// hostMounts lists the host directories and files that the lockdown must
// allow. An ext4lite volume needs none, because its image file is open before
// the lockdown.
func (s *Sandbox) hostMounts() []hostlockdown.HostMount {
	var list []hostlockdown.HostMount
	var metaIndices []int
	for _, m := range s.mounts {
		if m.Kind != MountTmpfs && m.Kind != MountOverlay && m.volume == nil {
			list = append(list, hostlockdown.HostMount{Path: m.hostPath, ReadOnly: m.ReadOnly, File: m.hostFile})
			if m.workspace != nil {
				if metaDir := m.workspace.MetaDir(); metaDir != "" {
					matched := false
					for _, idx := range metaIndices {
						if sameHostPath(list[idx].Path, metaDir) {
							list[idx].ReadOnly = list[idx].ReadOnly && m.ReadOnly
							matched = true
							break
						}
					}
					if !matched {
						metaIndices = append(metaIndices, len(list))
						list = append(list, hostlockdown.HostMount{Path: metaDir, ReadOnly: m.ReadOnly, File: false})
					}
				}
			}
		}
	}
	for _, sm := range s.serveMounts {
		if sm.hostPath != "" {
			list = append(list, hostlockdown.HostMount{Path: sm.hostPath, ReadOnly: sm.ReadOnly, File: sm.SingleFile})
		}
	}
	return list
}

// usesHostDirs reports whether a mount opened a host directory or file. Only
// then does the Linux seccomp filter need the host filesystem rules.
func (s *Sandbox) usesHostDirs() bool {
	for _, m := range s.mounts {
		if m.Kind != MountTmpfs && m.Kind != MountOverlay && m.volume == nil {
			return true
		}
	}
	for _, sm := range s.serveMounts {
		if sm.hostPath != "" {
			return true
		}
	}
	return false
}

func (s *Sandbox) openServeMountsForRestore() error {
	for _, sm := range s.cfg.ServeMounts {
		entry := sandboxServeMount{ServeMount: sm}
		if sm.Client == nil {
			absHost, err := filepath.Abs(sm.HostPath)
			if err != nil {
				return fmt.Errorf("gvx: resolve serve mount %s path %q: %w", sm.GuestPath, sm.HostPath, err)
			}
			for _, m := range s.mounts {
				if m.workspace == nil {
					continue
				}
				metaDir := m.workspace.MetaDir()
				if metaDir == "" {
					continue
				}
				if sameHostPath(absHost, metaDir) || hostPathContainsStrict(absHost, metaDir) || hostPathContainsStrict(metaDir, absHost) {
					return fmt.Errorf("gvx: serve mount %s host path %q overlaps mount %s MetaDir: %w", sm.GuestPath, sm.HostPath, m.GuestPath, ErrInvalidConfig)
				}
			}
			cli, openedHost, singleFile, err := openLocalRPCFSClient(sm.HostPath, sm.ReadOnly)
			if err != nil {
				return err
			}
			entry.hostPath = openedHost
			entry.SingleFile = singleFile
			entry.localClient = cli
			entry.Client = cli
		}
		s.serveMounts = append(s.serveMounts, entry)
	}
	return nil
}

func (s *Sandbox) closeServeMounts() {
	for _, sm := range s.serveMounts {
		if sm.localClient != nil {
			_ = sm.localClient.Close()
		}
	}
	s.serveMounts = nil
}

// closeMounts closes every hostfs workspace and every ext4lite volume once. The
// volume close compacts and truncates the image and marks it clean.
func (s *Sandbox) closeMounts() error {
	var errs []error
	for _, ws := range s.workspaces {
		if err := ws.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, h := range s.sandboxExtHandles {
		if err := hostlockdown.ReleaseFileExtension(h); err != nil {
			errs = append(errs, err)
		}
	}
	s.sandboxExtHandles = nil
	for _, vol := range s.volumes {
		if err := vol.Close(); err != nil {
			errs = append(errs, fmt.Errorf("gvx: close volume: %w", err))
		}
	}
	if s.rootVolume != nil {
		if err := s.rootVolume.Close(); err != nil {
			errs = append(errs, fmt.Errorf("gvx: close root volume: %w", err))
		}
		s.rootVolume = nil
	}
	s.workspaces = nil
	s.volumes = nil
	s.cappedVolumes = nil
	s.restoreBackingRO = nil
	s.mounts = nil
	s.workspace = nil
	s.rootUpperExisting = false
	return errors.Join(errs...)
}
