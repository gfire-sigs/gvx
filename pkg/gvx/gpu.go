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
	"strconv"
	"strings"
	"time"

	"z.gfire.dev/gvx/internal/gpurender"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvf"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// GPUMode selects the command stream of the virtual GPU of a sandbox.
type GPUMode string

const (
	// GPUOff gives the guest no GPU device. It is the zero value.
	GPUOff GPUMode = ""
	// GPUVenus gives the guest a virtio-gpu render node at /dev/dri/renderD128.
	// Mesa venus in the guest sends Vulkan commands to a confined host renderer
	// process, which runs them on the host GPU through KosmicKrisp and Metal. It
	// needs the hvf backend on darwin/arm64 (macOS 26 or later).
	GPUVenus GPUMode = "venus"
	// GPUVirgl gives the guest a virtio-gpu render node at
	// /dev/dri/renderD128. Mesa virgl in the guest sends OpenGL and OpenGL ES
	// commands to a confined host renderer process. That process runs them on
	// the host GPU through Apple OpenGL 4.1. It needs the hvf backend on
	// darwin/arm64 (macOS 26 or later).
	GPUVirgl GPUMode = "virgl"

	gpuKernelStopTimeout  = 30 * time.Second
	defaultGPUMemoryLimit = 4 << 30
	minGPUMacOSMajor      = 26
)

// String returns the CLI name of m: "off" for GPUOff.
func (m GPUMode) String() string {
	if m == GPUOff {
		return "off"
	}
	return string(m)
}

// GPUConfig turns on the virtual render node and its host renderer process.
type GPUConfig struct {
	// Mode selects the command stream: GPUVenus (Vulkan) or GPUVirgl (OpenGL).
	// GPUOff (the zero value) turns the GPU off.
	Mode GPUMode

	// RendererPath is the path of the gvx-gpu-renderer executable. When it is
	// empty, New searches the GVX_GPU_RENDERER environment variable, then the
	// directory of the current executable, then ../libexec next to it.
	RendererPath string

	// MemoryLimit is the largest sum of blob bytes that the guest can hold, in
	// bytes. Zero selects the default: the smaller of 4 GiB and 25% of host RAM.
	MemoryLimit uint64
}

var (
	// ErrGPUUnavailable reports that New cannot start the GPU renderer of a
	// sandbox that asked for a GPU. New never falls back to software rendering.
	ErrGPUUnavailable = errors.New("gvx: GPU renderer unavailable")

	errGPUAlreadyRegistered = errors.New("gvx: the GPU device is already registered")
)

// gpuHost is the GPU state of one sandbox. It holds the renderer client that
// New starts before the host lockdown and the render node that the kernel
// start registers. No other sandbox shares it.
type gpuHost struct {
	client      *gpurender.Client
	memoryLimit uint64
	// device is nil until registerGPU runs. Sandbox.mu guards it.
	device *virtgpu.Device
}

// gpuMemoryLimit returns the blob memory limit of the sandbox:
// Config.GPU.MemoryLimit, or the smaller of 4 GiB and a quarter of host RAM.
func gpuMemoryLimit(cfg GPUConfig, hostRAM uint64) uint64 {
	if cfg.MemoryLimit > 0 {
		return cfg.MemoryLimit
	}
	if hostRAM == 0 {
		return defaultGPUMemoryLimit
	}
	return min(defaultGPUMemoryLimit, hostRAM/4)
}

// ParseGPUMode parses a CLI or SDK GPU mode: "off" or "" (GPUOff), "venus"
// (GPUVenus), and "virgl" (GPUVirgl), without regard to case and surrounding
// spaces. ParseGPUMode reserves "auto". An unknown or reserved name returns an error
// that wraps ErrInvalidConfig.
func ParseGPUMode(s string) (GPUMode, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "", "off":
		return GPUOff, nil
	case "venus":
		return GPUVenus, nil
	case "virgl":
		return GPUVirgl, nil
	case "auto":
		return "", fmt.Errorf("%w: GPU mode %q is reserved and not supported (want off, venus, or virgl)", ErrInvalidConfig, v)
	default:
		return "", fmt.Errorf("%w: unsupported GPU mode %q (want off, venus, or virgl)", ErrInvalidConfig, v)
	}
}

// validateGPU rejects GPU settings that the host OS, the host architecture,
// the macOS version, or another option cannot satisfy. It reads c.GPU.Mode
// after ParseGPUMode has normalized it. Every error wraps ErrInvalidConfig.
func (c *Config) validateGPU(goos, goarch, macOS string) error {
	if c.GPU.Mode == GPUOff {
		if c.GPU.RendererPath != "" || c.GPU.MemoryLimit != 0 {
			return fmt.Errorf("%w: the GPU renderer path and the GPU memory limit need a GPU mode", ErrInvalidConfig)
		}
		return nil
	}
	if goos != "darwin" || goarch != "arm64" {
		return fmt.Errorf("%w: GPU mode %s needs a darwin/arm64 host, not %s/%s", ErrInvalidConfig, c.GPU.Mode, goos, goarch)
	}
	if macOS != "" {
		majorStr, _, _ := strings.Cut(macOS, ".")
		if major, err := strconv.Atoi(majorStr); err == nil && major < minGPUMacOSMajor {
			reason := "the KosmicKrisp driver needs Metal 4"
			if c.GPU.Mode == GPUVirgl {
				reason = "the renderer is built for macOS 26"
			}
			return fmt.Errorf("%w: GPU mode %s needs macOS 26 or later (%s); this host runs macOS %s", ErrInvalidConfig, c.GPU.Mode, reason, macOS)
		}
	}
	if c.Platform != PlatformAuto && c.Platform != PlatformHVF {
		return fmt.Errorf("%w: GPU mode %s needs the hvf backend, not %s", ErrInvalidConfig, c.GPU.Mode, c.Platform)
	}
	if c.CheckpointDir != "" || c.CheckpointListener != nil {
		return fmt.Errorf("%w: GPU mode %s cannot be combined with checkpoint: the renderer state is not saved", ErrInvalidConfig, c.GPU.Mode)
	}
	return nil
}

// refuseGPUCheckpointLocked rejects a checkpoint of a sandbox with a GPU.
// The bundle would not hold the renderer state. The control socket can ask
// for a checkpoint stream without Config.CheckpointDir, so validateGPU alone
// does not stop it. The caller holds s.mu.
func (s *Sandbox) refuseGPUCheckpointLocked() error {
	if s.gpu == nil {
		return nil
	}
	return fmt.Errorf("%w: a sandbox with a GPU cannot make a checkpoint: the renderer state is not saved", ErrInvalidConfig)
}

// refuseGPURestore rejects a restore configuration that asks for a GPU or sets
// GPU companion fields. Renderer state (Vulkan objects and GPU memory) is not
// part of a bundle.
func refuseGPURestore(gpu GPUConfig) error {
	mode, err := ParseGPUMode(string(gpu.Mode))
	if err != nil {
		return err
	}
	if mode != GPUOff {
		return fmt.Errorf("%w: GPU mode %s cannot restore a checkpoint: the renderer state is not saved", ErrInvalidConfig, mode)
	}
	if strings.TrimSpace(gpu.RendererPath) != "" || gpu.MemoryLimit != 0 {
		return fmt.Errorf("%w: the GPU renderer path and the GPU memory limit need a GPU mode", ErrInvalidConfig)
	}
	return nil
}

func logRendererLine(line string) {
	log.Infof("gvx-gpu-renderer: %s", line)
}

// startGPU locates and starts the GPU renderer of the sandbox before the host
// lockdown. It does nothing when the GPU is off. Every error wraps
// ErrGPUUnavailable or ErrPlatformUnavailable.
func (s *Sandbox) startGPU(ctx context.Context) error {
	if s.cfg.GPU.Mode == GPUOff {
		return nil
	}
	if s.platName != hvf.PlatformName {
		return fmt.Errorf("%w: GPU mode %s needs the hvf backend, but the sandbox opened %s", ErrPlatformUnavailable, s.cfg.GPU.Mode, s.platName)
	}
	path, err := gpurender.Locate(s.cfg.GPU.RendererPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGPUUnavailable, err)
	}
	ram, _ := hostMemory()
	limit := gpuMemoryLimit(s.cfg.GPU, ram)
	client, err := gpurender.Start(ctx, gpurender.Options{
		Path:        path,
		Log:         logRendererLine,
		MemoryLimit: limit,
		Mode:        rendererMode(s.cfg.GPU.Mode),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGPUUnavailable, err)
	}
	s.gpu = &gpuHost{client: client, memoryLimit: limit}
	return nil
}

// rendererMode returns the renderer mode of m. It panics on GPUOff, which
// startGPU never passes.
func rendererMode(m GPUMode) gpuproto.Mode {
	switch m {
	case GPUVenus:
		return gpuproto.ModeVenus
	case GPUVirgl:
		return gpuproto.ModeVirgl
	}
	panic(fmt.Sprintf("gvx: no renderer mode for GPU mode %q", m))
}

// registerGPU registers the render node of the sandbox with vfsObj. Call it
// once for each kernel, before the devtmpfs mount. It does nothing when the
// GPU is off.
func (s *Sandbox) registerGPU(vfsObj *vfs.VirtualFilesystem) error {
	s.mu.Lock()
	g := s.gpu
	if g == nil {
		s.mu.Unlock()
		return nil
	}
	if g.device != nil {
		s.mu.Unlock()
		return errGPUAlreadyRegistered
	}
	client := g.client
	limit := g.memoryLimit
	s.mu.Unlock()

	dev, err := virtgpu.Register(vfsObj, client, virtgpu.Limits{BlobBytes: limit})
	if err != nil {
		return fmt.Errorf("gvx: register the GPU render node: %w", err)
	}

	s.mu.Lock()
	if s.gpu == g {
		g.device = dev
	}
	s.mu.Unlock()
	return nil
}

// sysfsData returns the sysfs InternalData of the sandbox, or nil when the GPU
// is off. sysfs then builds the tree it builds today.
func (s *Sandbox) sysfsData() *sys.InternalData {
	s.mu.Lock()
	hasGPU := s.gpu != nil
	s.mu.Unlock()
	if !hasGPU {
		return nil
	}
	return &sys.InternalData{
		VirtGPU: &sys.VirtGPUSysfs{
			DevMajor: virtgpu.DRMMajor,
			DevMinor: virtgpu.RenderMinor,
		},
	}
}

// stopKernelForGPU makes sure that no guest task of a GPU sandbox can run.
// It kills the running kernel and waits until Run returns. It reports false
// when Run did not return within gpuKernelStopTimeout. A sandbox without a GPU
// returns true at once and keeps today's Close behavior.
func (s *Sandbox) stopKernelForGPU() bool {
	s.mu.Lock()
	if s.gpu == nil {
		s.mu.Unlock()
		return true
	}
	s.gpuClosing = true
	started := s.runStarted
	k := s.runningKernel
	done := s.runDone
	s.mu.Unlock()
	if !started {
		return true
	}
	if k != nil {
		k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
	}
	timer := time.NewTimer(gpuKernelStopTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		log.Warningf("gvx: the guest kernel did not stop within %v; GPU blob views stay mapped", gpuKernelStopTimeout)
		return false
	}
}

// closeGPU ends the renderer of the sandbox and, when releaseViews is true,
// releases the device's claim on leftover blob views. The caller holds s.mu
// and has closed the platform.
func (s *Sandbox) closeGPU(releaseViews bool) {
	if s.gpu == nil {
		return
	}
	_ = s.gpu.client.Close()
	if releaseViews && s.gpu.device != nil {
		s.gpu.device.ReleaseBlobViews()
	}
	s.gpu = nil
}
