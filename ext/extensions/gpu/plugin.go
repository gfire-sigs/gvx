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

// Package gpu integrates the optional virtio-gpu extension with rungvx and the
// gvx Sandbox Extension SPI behind the ext_gpu and ext_all build tags.
package gpu

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"sync"

	gpurender "z.gfire.dev/gvx/ext/extensions/gpu/client"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
	"z.gfire.dev/gvx/ext/extensions/gpu/virtgpu"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
)

// Mode selects the guest GPU acceleration protocol.
type Mode string

const (
	ModeOff   Mode = "off"
	ModeVenus Mode = "venus"
	ModeVirgl Mode = "virgl"

	defaultMemoryLimit uint64 = 4 << 30
	minMacOSMajor             = 26
)

// ErrRendererUnavailable reports that the external gvx-gpu-renderer worker
// binary cannot be located or started. The runtime never falls back silently
// to software rendering.
var ErrRendererUnavailable = errors.New("gpu: gvx-gpu-renderer worker unavailable")

var errAlreadyAttached = errors.New("gpu: render node already attached to kernel")

// Options configures one GPU Sandbox Extension instance.
type Options struct {
	Mode             Mode
	RendererPath     string
	MemoryLimitBytes uint64
}

// ParseMode validates a GPU mode string ("off", "venus", or "virgl").
// The value "auto" is reserved and rejected with gvx.ErrInvalidConfig so callers
// never receive silent software fallback.
func ParseMode(raw string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(raw))); m {
	case "", ModeOff:
		return ModeOff, nil
	case ModeVenus, ModeVirgl:
		return m, nil
	case "auto":
		return "", fmt.Errorf("%w: -gpu mode %q is reserved and unsupported (want off, venus, or virgl)", gvx.ErrInvalidConfig, raw)
	default:
		return "", fmt.Errorf("%w: unsupported -gpu mode %q (want off, venus, or virgl)", gvx.ErrInvalidConfig, raw)
	}
}

// ParseMemoryLimit parses a GPU memory budget such as "512m", "2g", or raw bytes.
func ParseMemoryLimit(raw string) (uint64, error) {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" || s == "0" {
		return 0, nil
	}
	var mult uint64 = 1
	switch {
	case strings.HasSuffix(s, "gib"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "gib")
	case strings.HasSuffix(s, "g"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "g")
	case strings.HasSuffix(s, "mib"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "mib")
	case strings.HasSuffix(s, "m"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "m")
	case strings.HasSuffix(s, "kib"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "kib")
	case strings.HasSuffix(s, "k"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "k")
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%w: invalid -gpu-memory-limit %q", gvx.ErrInvalidConfig, raw)
	}
	if n > ^uint64(0)/mult {
		return 0, fmt.Errorf("%w: -gpu-memory-limit %q overflows uint64", gvx.ErrInvalidConfig, raw)
	}
	return n * mult, nil
}

func effectiveMemoryLimit(configured, hostRAM uint64) uint64 {
	if configured > 0 {
		return configured
	}
	if hostRAM == 0 {
		return defaultMemoryLimit
	}
	return min(defaultMemoryLimit, hostRAM/4)
}

func parseMacOSMajor(version string) (int, bool) {
	head, _, _ := strings.Cut(strings.TrimSpace(version), ".")
	if head == "" {
		return 0, false
	}
	major, err := strconv.Atoi(head)
	if err != nil || major <= 0 {
		return 0, false
	}
	return major, true
}

func rendererProtoMode(m Mode) (gpuproto.Mode, error) {
	switch m {
	case ModeVenus:
		return gpuproto.ModeVenus, nil
	case ModeVirgl:
		return gpuproto.ModeVirgl, nil
	default:
		return 0, fmt.Errorf("%w: gpu extension requires mode venus or virgl", gvx.ErrInvalidConfig)
	}
}

// Extension implements gvx.Extension for optional virtio-gpu acceleration.
type Extension struct {
	opts Options
	// macOSVersion overrides hostMacOSVersion in unit tests when non-nil.
	macOSVersion func() string
}

// NewExtension constructs an immutable GPU Extension from opts.
func NewExtension(opts Options) *Extension {
	return &Extension{opts: opts}
}

// Name implements gvx.Extension.Name.
func (*Extension) Name() string {
	return "gpu"
}

// Options returns a copy of the configured extension options.
func (e *Extension) Options() Options {
	return e.opts
}

// Validate implements gvx.Extension.Validate.
func (e *Extension) Validate(env gvx.ValidationEnv) error {
	mode, err := ParseMode(string(e.opts.Mode))
	if err != nil {
		return err
	}
	if mode == ModeOff {
		return fmt.Errorf("%w: gpu extension requires mode venus or virgl", gvx.ErrInvalidConfig)
	}
	if env.IsRestore || env.HasCheckpoint {
		return gvx.ErrCheckpointExtensionUnsupported
	}
	if env.GOOS != "darwin" || env.GOARCH != "arm64" {
		return fmt.Errorf("%w: GPU mode %s requires darwin/arm64, got %s/%s", gvx.ErrPlatformUnavailable, mode, env.GOOS, env.GOARCH)
	}
	versionFn := hostMacOSVersion
	if e.macOSVersion != nil {
		versionFn = e.macOSVersion
	}
	if ver := versionFn(); ver != "" {
		if major, ok := parseMacOSMajor(ver); ok && major < minMacOSMajor {
			return fmt.Errorf("%w: GPU mode %s requires macOS %d or later, got %s", gvx.ErrPlatformUnavailable, mode, minMacOSMajor, ver)
		}
	}
	if env.Platform != "" && env.Platform != gvx.PlatformAuto && env.Platform != gvx.PlatformHVF {
		return fmt.Errorf("%w: GPU mode %s requires the hvf backend, got %q", gvx.ErrPlatformUnavailable, mode, env.Platform)
	}
	return nil
}

// OpenPreLockdown implements gvx.Extension.OpenPreLockdown. It locates and
// launches gvx-gpu-renderer before hostlockdown.Apply runs.
func (e *Extension) OpenPreLockdown(ctx context.Context, env gvx.PreLockdownEnv) (gvx.BoundExtension, error) {
	mode, err := ParseMode(string(e.opts.Mode))
	if err != nil {
		return nil, err
	}
	protoMode, err := rendererProtoMode(mode)
	if err != nil {
		return nil, err
	}
	if env.PlatformName != "hvf" {
		return nil, fmt.Errorf("%w: GPU mode %s requires the hvf backend, got %q", gvx.ErrPlatformUnavailable, mode, env.PlatformName)
	}
	path, err := gpurender.Locate(e.opts.RendererPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRendererUnavailable, err)
	}
	topo, err := virtgpu.SysfsTopology()
	if err != nil {
		return nil, fmt.Errorf("gpu: build sysfs topology: %w", err)
	}
	limit := effectiveMemoryLimit(e.opts.MemoryLimitBytes, env.HostRAMBytes)
	var logLine func(string)
	if env.Logf != nil {
		logLine = func(line string) {
			env.Logf("gvx-gpu-renderer: %s", line)
		}
	}
	client, err := gpurender.Start(ctx, gpurender.Options{
		Path:        path,
		Log:         logLine,
		MemoryLimit: limit,
		Mode:        protoMode,
		SpawnHelper: env.SpawnHelper,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRendererUnavailable, err)
	}
	return &boundGPU{
		mode:        mode,
		memoryLimit: limit,
		topo:        topo,
		client:      client,
	}, nil
}

type boundGPU struct {
	mode        Mode
	memoryLimit uint64
	topo        sys.TopologyAddition

	mu      sync.Mutex
	client  *gpurender.Client
	dev     *virtgpu.Device
	aborted bool
}

var _ gvx.BoundExtension = (*boundGPU)(nil)

func (*boundGPU) NeedsHelperSpawn() bool {
	return true
}

func (*boundGPU) LockdownRequirements() gvx.ExtensionLockdown {
	return gvx.ExtensionLockdown{}
}

func (*boundGPU) CheckpointPolicy() gvx.CheckpointPolicy {
	return gvx.CheckpointUnsupported
}

func (b *boundGPU) SysfsTopologies() []sys.TopologyAddition {
	return []sys.TopologyAddition{b.topo}
}

func (b *boundGPU) AttachKernel(_ context.Context, kenv *gvx.KernelEnv) error {
	b.mu.Lock()
	if b.aborted || b.client == nil {
		b.mu.Unlock()
		return gvx.ErrSandboxClosing
	}
	if b.dev != nil {
		b.mu.Unlock()
		return errAlreadyAttached
	}
	client := b.client
	limit := b.memoryLimit
	b.mu.Unlock()

	dev, err := virtgpu.RegisterWithImporter(kenv.VFS, client, kenv.SharedMemory, virtgpu.Limits{BlobBytes: limit})
	if err != nil {
		return fmt.Errorf("gpu: register render node: %w", err)
	}

	b.mu.Lock()
	if b.aborted || b.client == nil {
		b.mu.Unlock()
		dev.ReleaseBlobViews()
		return gvx.ErrSandboxClosing
	}
	b.dev = dev
	b.mu.Unlock()
	return nil
}

func (b *boundGPU) AbortPending() {
	b.mu.Lock()
	b.aborted = true
	client := b.client
	b.client = nil
	b.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
}

func (b *boundGPU) Close(guestUnmapped bool) error {
	b.mu.Lock()
	b.aborted = true
	client := b.client
	b.client = nil
	var dev *virtgpu.Device
	if guestUnmapped {
		dev = b.dev
		b.dev = nil
	}
	b.mu.Unlock()

	var err error
	if client != nil {
		err = client.Close()
	}
	if dev != nil {
		dev.ReleaseBlobViews()
	}
	return err
}

func (b *boundGPU) snapshot() map[string]any {
	b.mu.Lock()
	client := b.client
	dev := b.dev
	aborted := b.aborted
	b.mu.Unlock()

	out := map[string]any{
		"mode":               string(b.mode),
		"memory_limit_bytes": b.memoryLimit,
		"aborted":            aborted,
	}
	if dev != nil {
		out["blob_bytes"] = dev.BlobBytes()
	}
	if client != nil {
		out["renderer_pid"] = client.PID()
		out["renderer_build"] = client.Build()
	}
	return out
}

func (b *boundGPU) Inspect() (json.RawMessage, error) {
	return json.Marshal(b.snapshot())
}

func (b *boundGPU) Stats() (json.RawMessage, error) {
	return json.Marshal(b.snapshot())
}

// CLIPlugin integrates GPU flags and build metadata into rungvx.
type CLIPlugin struct {
	modeRaw     string
	renderer    string
	memLimitRaw string
}

// NewCLIPlugin returns a fresh CLIPlugin instance for rungvx.MainWithPlugins.
func NewCLIPlugin() *CLIPlugin {
	return &CLIPlugin{}
}

// Name implements rungvx.CLIPlugin.Name.
func (*CLIPlugin) Name() string {
	return "gpu"
}

// BuildSummary implements rungvx.CLIPlugin.BuildSummary.
func (*CLIPlugin) BuildSummary() string {
	return "modes=venus,virgl"
}

// RegisterFlags implements rungvx.CLIPlugin.RegisterFlags.
func (p *CLIPlugin) RegisterFlags(fs *flag.FlagSet) {
	p.modeRaw = ""
	p.renderer = ""
	p.memLimitRaw = ""
	fs.StringVar(&p.modeRaw, "gpu", "", "Enable virtio-gpu acceleration (off, venus, virgl)")
	fs.StringVar(&p.renderer, "gpu-renderer", "", "Path to the external gvx-gpu-renderer worker binary")
	fs.StringVar(&p.memLimitRaw, "gpu-memory-limit", "", "Maximum imported GPU shared memory per sandbox (for example 512m, 2g)")
}

// ApplyConfig implements rungvx.CLIPlugin.ApplyConfig.
func (p *CLIPlugin) ApplyConfig(cfg *gvx.Config) error {
	mode, err := ParseMode(p.modeRaw)
	if err != nil {
		return err
	}
	limitBytes, err := ParseMemoryLimit(p.memLimitRaw)
	if err != nil {
		return err
	}
	if mode == ModeOff {
		if strings.TrimSpace(p.renderer) != "" || limitBytes > 0 {
			return fmt.Errorf("%w: -gpu-renderer and -gpu-memory-limit require -gpu", gvx.ErrInvalidConfig)
		}
		return nil
	}
	cfg.Extensions = append(cfg.Extensions, NewExtension(Options{
		Mode:             mode,
		RendererPath:     strings.TrimSpace(p.renderer),
		MemoryLimitBytes: limitBytes,
	}))
	return nil
}
