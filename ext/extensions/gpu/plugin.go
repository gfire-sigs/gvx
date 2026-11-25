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
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

// Mode selects the guest GPU acceleration protocol.
type Mode string

const (
	ModeOff   Mode = "off"
	ModeAuto  Mode = "auto"
	ModeVenus Mode = "venus"
	ModeVirgl Mode = "virgl"
)

// ErrRendererUnavailable reports that no external gvx-gpu-renderer worker
// binary is installed or wired for this host yet.
var ErrRendererUnavailable = errors.New("gpu: external gvx-gpu-renderer worker is unavailable")

// Options configures one GPU Sandbox Extension instance.
type Options struct {
	Mode             Mode
	RendererPath     string
	MemoryLimitBytes uint64
}

// ParseMode validates a GPU mode string ("off", "auto", "venus", or "virgl").
func ParseMode(raw string) (Mode, error) {
	switch m := Mode(strings.ToLower(strings.TrimSpace(raw))); m {
	case "", ModeOff:
		return ModeOff, nil
	case ModeAuto, ModeVenus, ModeVirgl:
		return m, nil
	default:
		return "", fmt.Errorf("%w: unsupported -gpu mode %q (want off, auto, venus, or virgl)", gvx.ErrInvalidConfig, raw)
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

// Extension implements gvx.Extension for optional GPU acceleration.
type Extension struct {
	opts Options
}

// NewExtension constructs an immutable GPU Extension from opts.
func NewExtension(opts Options) *Extension {
	if opts.Mode == "" {
		opts.Mode = ModeAuto
	}
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
		return fmt.Errorf("%w: gpu extension requires mode auto, venus, or virgl", gvx.ErrInvalidConfig)
	}
	if env.IsRestore || env.HasCheckpoint {
		return gvx.ErrCheckpointExtensionUnsupported
	}
	return nil
}

// OpenPreLockdown implements gvx.Extension.OpenPreLockdown.
func (e *Extension) OpenPreLockdown(_ context.Context, _ gvx.PreLockdownEnv) (gvx.BoundExtension, error) {
	return nil, fmt.Errorf("%w: mode=%s requires gvx-gpu-renderer worker (Stage 5)", ErrRendererUnavailable, e.opts.Mode)
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
	fs.StringVar(&p.modeRaw, "gpu", "", "Enable virtio-gpu acceleration (off, auto, venus, virgl)")
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
