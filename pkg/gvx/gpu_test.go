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
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

func TestConfigGPUParseMode(t *testing.T) {
	if got := GPUOff.String(); got != "off" {
		t.Errorf("GPUOff.String() = %q, want %q", got, "off")
	}
	if got := GPUVenus.String(); got != "venus" {
		t.Errorf("GPUVenus.String() = %q, want %q", got, "venus")
	}
	if got := GPUVirgl.String(); got != "virgl" {
		t.Errorf("GPUVirgl.String() = %q, want %q", got, "virgl")
	}

	for _, tc := range []struct {
		name    string
		input   string
		want    GPUMode
		wantErr string
	}{
		{"empty", "", GPUOff, ""},
		{"off", "off", GPUOff, ""},
		{"off with case and spaces", " Off ", GPUOff, ""},
		{"venus", "venus", GPUVenus, ""},
		{"venus uppercase", "VENUS", GPUVenus, ""},
		{"virgl", "virgl", GPUVirgl, ""},
		{"virgl uppercase", "VIRGL", GPUVirgl, ""},
		{"virgl with spaces", " virgl ", GPUVirgl, ""},
		{"reserved auto", "auto", "", "reserved"},
		{"unknown vulkan", "vulkan", "", "unsupported GPU mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseGPUMode(tc.input)
			if tc.wantErr != "" {
				if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseGPUMode(%q) = (%q, %v), want ErrInvalidConfig containing %q", tc.input, got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParseGPUMode(%q) = (%q, %v), want (%q, nil)", tc.input, got, err, tc.want)
			}
		})
	}
}

func TestConfigGPUValidation(t *testing.T) {
	ckptDir := t.TempDir()
	for _, tc := range []struct {
		name    string
		cfg     Config
		goos    string
		goarch  string
		macOS   string
		wantErr string
	}{
		{
			name:   "gpu off on linux amd64",
			cfg:    Config{Platform: PlatformAuto},
			goos:   "linux",
			goarch: "amd64",
			macOS:  "27.2.1",
		},
		{
			name:   "venus with auto on darwin arm64 macOS 27.2.1",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "27.2.1",
		},
		{
			name:   "venus with auto on darwin arm64 macOS 26.0",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "26.0",
		},
		{
			name:    "venus on macOS 15.7.3",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "15.7.3",
			wantErr: "macOS 26 or later",
		},
		{
			name:   "venus with empty macOS version",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "",
		},
		{
			name:   "venus with unparsable macOS version",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "unknown",
		},
		{
			name:   "venus with hvf on darwin arm64",
			cfg:    Config{Platform: PlatformHVF, GPU: GPUConfig{Mode: GPUVenus}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "27.2.1",
		},
		{
			name:    "venus on linux arm64",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:    "linux",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "darwin/arm64",
		},
		{
			name:    "venus on windows amd64",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:    "windows",
			goarch:  "amd64",
			macOS:   "27.2.1",
			wantErr: "darwin/arm64",
		},
		{
			name:    "venus on darwin amd64",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}},
			goos:    "darwin",
			goarch:  "amd64",
			macOS:   "27.2.1",
			wantErr: "darwin/arm64",
		},
		{
			name:    "venus with systrap",
			cfg:     Config{Platform: PlatformSystrap, GPU: GPUConfig{Mode: GPUVenus}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "hvf backend",
		},
		{
			name:    "venus with whpx",
			cfg:     Config{Platform: PlatformWHPX, GPU: GPUConfig{Mode: GPUVenus}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "hvf backend",
		},
		{
			name:    "venus with checkpoint dir",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}, CheckpointDir: ckptDir},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "checkpoint",
		},
		{
			name:   "venus with checkpoint listener",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}, CheckpointListener: new(net.TCPListener)},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "27.2.1",
		},
		{
			name:   "virgl with checkpoint listener",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVirgl}, CheckpointListener: new(net.TCPListener)},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "27.2.1",
		},
		{
			name:    "off with renderer path",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUOff, RendererPath: "/x"}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "need a GPU mode",
		},
		{
			name:    "off with memory limit",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUOff, MemoryLimit: 1}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "need a GPU mode",
		},
		{
			name:   "virgl with auto on darwin arm64 macOS 26.0",
			cfg:    Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVirgl}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "26.0",
		},
		{
			name:   "virgl with hvf on darwin arm64",
			cfg:    Config{Platform: PlatformHVF, GPU: GPUConfig{Mode: GPUVirgl}},
			goos:   "darwin",
			goarch: "arm64",
			macOS:  "27.2.1",
		},
		{
			name:    "virgl on linux arm64",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVirgl}},
			goos:    "linux",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "darwin/arm64",
		},
		{
			name:    "virgl on darwin arm64 macOS 25.4",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVirgl}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "25.4",
			wantErr: "built for macOS 26",
		},
		{
			name:    "virgl with systrap",
			cfg:     Config{Platform: PlatformSystrap, GPU: GPUConfig{Mode: GPUVirgl}},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "hvf backend",
		},
		{
			name:    "virgl with checkpoint dir",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVirgl}, CheckpointDir: ckptDir},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "checkpoint",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validateGPU(tc.goos, tc.goarch, tc.macOS)
			if tc.wantErr != "" {
				if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("validateGPU(%s, %s, %q) = %v, want ErrInvalidConfig containing %q", tc.goos, tc.goarch, tc.macOS, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateGPU(%s, %s, %q) = %v, want nil", tc.goos, tc.goarch, tc.macOS, err)
			}
		})
	}
}

func TestConfigGPUNormalizeOnThisHost(t *testing.T) {
	venusCfg := Config{GPU: GPUConfig{Mode: "VENUS"}}
	err := venusCfg.normalize()
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if err != nil {
			t.Fatalf("normalize(VENUS) on darwin/arm64 = %v, want nil", err)
		}
		if venusCfg.GPU.Mode != GPUVenus {
			t.Fatalf("GPU.Mode = %q, want %q", venusCfg.GPU.Mode, GPUVenus)
		}
	} else {
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "darwin/arm64") {
			t.Fatalf("normalize(VENUS) on %s/%s = %v, want ErrInvalidConfig containing %q", runtime.GOOS, runtime.GOARCH, err, "darwin/arm64")
		}
	}

	offCfg := Config{GPU: GPUConfig{Mode: "off"}}
	if err := offCfg.normalize(); err != nil {
		t.Fatalf("normalize(off) = %v, want nil", err)
	}
	if offCfg.GPU.Mode != GPUOff {
		t.Fatalf("GPU.Mode = %q, want %q", offCfg.GPU.Mode, GPUOff)
	}
}

func TestConfigGPUNormalizeTrimsRendererPath(t *testing.T) {
	offCfg := Config{GPU: GPUConfig{Mode: GPUOff, RendererPath: "  \t "}}
	if err := offCfg.normalize(); err != nil {
		t.Fatalf("normalize(off with whitespace RendererPath) = %v, want nil", err)
	}
	if offCfg.GPU.RendererPath != "" {
		t.Fatalf("GPU.RendererPath = %q, want empty", offCfg.GPU.RendererPath)
	}

	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return
	}
	paddedCfg := Config{GPU: GPUConfig{Mode: GPUVenus, RendererPath: "  /opt/r/bin/gvx-gpu-renderer  "}}
	if err := paddedCfg.normalize(); err != nil {
		t.Fatalf("normalize(venus with padded RendererPath) = %v, want nil", err)
	}
	if paddedCfg.GPU.RendererPath != "/opt/r/bin/gvx-gpu-renderer" {
		t.Fatalf("GPU.RendererPath = %q, want %q", paddedCfg.GPU.RendererPath, "/opt/r/bin/gvx-gpu-renderer")
	}

	blankCfg := Config{GPU: GPUConfig{Mode: GPUVenus, RendererPath: "   "}}
	if err := blankCfg.normalize(); err != nil {
		t.Fatalf("normalize(venus with blank RendererPath) = %v, want nil", err)
	}
	if blankCfg.GPU.RendererPath != "" {
		t.Fatalf("GPU.RendererPath = %q, want empty", blankCfg.GPU.RendererPath)
	}
}

func TestConfigGPURestoreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		gpu  GPUConfig
		want string
	}{
		{"venus mode", GPUConfig{Mode: GPUVenus}, "cannot restore"},
		{"virgl mode", GPUConfig{Mode: GPUVirgl}, "cannot restore"},
		{"off with renderer path", GPUConfig{Mode: GPUOff, RendererPath: "/opt/r"}, "need a GPU mode"},
		{"off with memory limit", GPUConfig{Mode: GPUOff, MemoryLimit: 1}, "need a GPU mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb, err := Restore(context.Background(), Config{GPU: tc.gpu}, RestoreOptions{Dir: t.TempDir()})
			if sb != nil {
				_ = sb.Close()
				t.Fatalf("Restore(%+v) returned non-nil sandbox", tc.gpu)
			}
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Restore(%+v) error = %v, want ErrInvalidConfig containing %q", tc.gpu, err, tc.want)
			}
			if errors.Is(err, ErrCheckpointManifest) {
				t.Fatalf("Restore(%+v) error = %v, must not wrap ErrCheckpointManifest", tc.gpu, err)
			}
		})
	}
}

func TestNewGPURejectsConfigBeforeOpeningHandles(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "never-created")
	sb, err := New(context.Background(), Config{
		GPU:         GPUConfig{Mode: GPUVenus},
		Platform:    PlatformSystrap,
		OCICacheDir: cacheDir,
	})
	if sb != nil {
		_ = sb.Close()
		t.Fatalf("New(GPUVenus, systrap) returned non-nil sandbox")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(GPUVenus, systrap) error = %v, want ErrInvalidConfig", err)
	}
	if _, statErr := os.Stat(cacheDir); !os.IsNotExist(statErr) {
		t.Fatalf("New created cache dir before rejecting GPU config: stat error = %v", statErr)
	}
}

func TestGPUMemoryLimitDefault(t *testing.T) {
	const gib = 1 << 30
	for _, tc := range []struct {
		name    string
		cfg     GPUConfig
		hostRAM uint64
		want    uint64
	}{
		{"64 GiB host uses 4 GiB cap", GPUConfig{}, 64 * gib, 4 * gib},
		{"8 GiB host uses quarter RAM", GPUConfig{}, 8 * gib, 2 * gib},
		{"unknown host RAM uses 4 GiB", GPUConfig{}, 0, 4 * gib},
		{"explicit 1 GiB overrides default", GPUConfig{MemoryLimit: 1 * gib}, 64 * gib, 1 * gib},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := gpuMemoryLimit(tc.cfg, tc.hostRAM); got != tc.want {
				t.Fatalf("gpuMemoryLimit(%+v, %d) = %d, want %d", tc.cfg, tc.hostRAM, got, tc.want)
			}
		})
	}
}

func TestRendererMode(t *testing.T) {
	if got := rendererMode(GPUVenus); got != gpuproto.ModeVenus {
		t.Fatalf("rendererMode(GPUVenus) = %v, want %v", got, gpuproto.ModeVenus)
	}
	if got := rendererMode(GPUVirgl); got != gpuproto.ModeVirgl {
		t.Fatalf("rendererMode(GPUVirgl) = %v, want %v", got, gpuproto.ModeVirgl)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("rendererMode(GPUOff) did not panic")
		}
	}()
	_ = rendererMode(GPUOff)
}

// TestCheckpointRefusesGPUSandbox verifies that the file and stream
// checkpoint paths refuse a sandbox configured with a GPU, both while the
// renderer is live and after closeGPU(false) clears s.gpu.
func TestCheckpointRefusesGPUSandbox(t *testing.T) {
	for _, tc := range []struct {
		name string
		sb   *Sandbox
	}{
		{
			name: "venus with live renderer",
			sb:   &Sandbox{cfg: Config{GPU: GPUConfig{Mode: GPUVenus}}, gpu: &gpuHost{}},
		},
		{
			name: "venus after renderer closed",
			sb:   &Sandbox{cfg: Config{GPU: GPUConfig{Mode: GPUVenus}}},
		},
		{
			name: "virgl after renderer closed",
			sb:   &Sandbox{cfg: Config{GPU: GPUConfig{Mode: GPUVirgl}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.sb.Checkpoint(context.Background(), CheckpointOptions{}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Checkpoint error = %v, want ErrInvalidConfig", err)
			}
			if err := tc.sb.CheckpointStream(context.Background(), CheckpointOptions{}, nil); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("CheckpointStream error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// TestGPUControlSocketRefusesCheckpointAndAllowsPing verifies that a GPU
// sandbox with CheckpointListener serves non-checkpoint control RPCs and
// refuses v2 local, v2 stream, and legacy v1 checkpoint requests cleanly.
func TestGPUControlSocketRefusesCheckpointAndAllowsPing(t *testing.T) {
	for _, tc := range []struct {
		name            string
		setControlField bool
	}{
		{name: "checkpoint listener only", setControlField: false},
		{name: "control and checkpoint listeners shared", setControlField: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sockPath := shortControlSocketPath(t, "gpu-ctrl.sock")
			ep, err := control.Listen(sockPath, control.ListenOptions{})
			if err != nil {
				t.Fatalf("control.Listen(%q): %v", sockPath, err)
			}
			t.Cleanup(ep.Cleanup)

			cfg := Config{
				Name:               "gpu-ctrl-test",
				GPU:                GPUConfig{Mode: GPUVenus},
				CheckpointListener: ep.Listener,
				ControlToken:       ep.Token,
			}
			if tc.setControlField {
				cfg.ControlListener = ep.Listener
			}
			sb := &Sandbox{
				cfg:         cfg,
				kernelReady: make(chan struct{}),
				runDone:     make(chan struct{}),
			}
			sb.initControlState()

			serveCtx, serveCancel := context.WithCancel(context.Background())
			serveDone := make(chan struct{})
			go func() {
				defer close(serveDone)
				_ = sb.ServeControl(serveCtx)
			}()
			t.Cleanup(func() {
				drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = sb.ShutdownControl(drainCtx)
				drainCancel()
				serveCancel()
				_ = ep.Listener.Close()
				<-serveDone
			})

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			client, err := control.Dial(ctx, control.DialOptions{
				Endpoint: sockPath,
				Token:    ep.Token,
			})
			if err != nil {
				t.Fatalf("control.Dial: %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })

			var pingResp control.PingResponse
			if err := client.Call(ctx, control.MethodPing, nil, &pingResp); err != nil {
				t.Fatalf("MethodPing: %v", err)
			}
			if pingResp.SandboxID != "gpu-ctrl-test" {
				t.Fatalf("PingResponse.SandboxID = %q, want %q", pingResp.SandboxID, "gpu-ctrl-test")
			}

			err = client.Call(ctx, control.MethodCheckpointStream, control.CheckpointStreamRequest{}, nil)
			if !control.IsCode(err, control.CodeInvalidArgument) || !strings.Contains(err.Error(), "renderer state is not saved") {
				t.Fatalf("MethodCheckpointStream error = %v, want INVALID_ARGUMENT mentioning renderer state", err)
			}

			err = client.Call(ctx, control.MethodCheckpoint, control.CheckpointRequest{}, nil)
			if !control.IsCode(err, control.CodeForbiddenByPolicy) {
				t.Fatalf("MethodCheckpoint error = %v, want FORBIDDEN_BY_POLICY", err)
			}

			rawConn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
			if err != nil {
				t.Fatalf("dial legacy v1: %v", err)
			}
			t.Cleanup(func() { _ = rawConn.Close() })
			_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := json.NewEncoder(rawConn).Encode(control.LegacyCheckpointRequest{Token: ep.Token}); err != nil {
				t.Fatalf("encode legacy v1 request: %v", err)
			}
			var legacyResp control.LegacyCheckpointResponse
			if err := json.NewDecoder(rawConn).Decode(&legacyResp); err != nil {
				t.Fatalf("decode legacy v1 response: %v", err)
			}
			if legacyResp.OK || legacyResp.Error == "" {
				t.Fatalf("legacy v1 checkpoint response = %+v, want OK=false with error", legacyResp)
			}
		})
	}
}

type fakeKernelPlatform struct {
	platform.Platform
}

func (fakeKernelPlatform) HasCPUNumbers() bool { return false }

// TestStopKernelForGPUUnpausesBeforeKill verifies that stopKernelForGPU
// unpauses a paused kernel before killing it and blocks later Pause calls.
func TestStopKernelForGPUUnpausesBeforeKill(t *testing.T) {
	initRuntimeGlobals()
	mf, err := createKernelMemoryFile(0, false)
	if err != nil {
		t.Fatalf("createKernelMemoryFile: %v", err)
	}
	defer mf.Destroy()

	readyCh := make(chan struct{})
	close(readyCh)
	doneCh := make(chan struct{})
	close(doneCh)

	sb := &Sandbox{
		cfg:         Config{GPU: GPUConfig{Mode: GPUVenus}},
		plat:        fakeKernelPlatform{},
		kernelReady: readyCh,
		runDone:     doneCh,
	}
	sb.initControlState()

	k, tk, _, cleanupNetLog, err := sb.initFreshKernel(mf, 0)
	if err != nil {
		t.Fatalf("initFreshKernel: %v", err)
	}
	defer tk.Destroy()
	defer cleanupNetLog()

	k.Pause()
	if !k.IsPaused() {
		t.Fatal("kernel is not paused after Pause")
	}

	sb.mu.Lock()
	sb.gpu = &gpuHost{}
	sb.runStarted = true
	sb.runningKernel = k
	sb.activeKernel = k
	sb.userPaused = true
	sb.mu.Unlock()

	if !sb.stopKernelForGPU() {
		t.Fatal("stopKernelForGPU = false, want true")
	}
	if k.IsPaused() {
		t.Fatal("kernel remains paused after stopKernelForGPU")
	}
	if !k.TaskSet().IsExiting() {
		t.Fatal("kernel task set is not exiting after stopKernelForGPU")
	}
	sb.mu.Lock()
	paused := sb.userPaused
	closing := sb.gpuClosing
	sb.mu.Unlock()
	if paused {
		t.Fatal("userPaused remains true after stopKernelForGPU")
	}
	if !closing {
		t.Fatal("gpuClosing is false after stopKernelForGPU")
	}
	if err := sb.Pause(context.Background(), false); !control.IsCode(err, control.CodeSandboxExiting) {
		t.Fatalf("Pause after stopKernelForGPU = %v, want SANDBOX_EXITING", err)
	}
}

// TestGPUCloseTimeoutRetriesAfterKernelStops verifies that a timed-out GPU
// Close closes control endpoints without permanently leaking the platform and
// memory file, and that a later Close releases them once the kernel stops.
func TestGPUCloseTimeoutRetriesAfterKernelStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mf, err := createKernelMemoryFile(0, false)
		if err != nil {
			t.Fatalf("createKernelMemoryFile: %v", err)
		}
		backing := mf.File()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			mf.Destroy()
			t.Fatalf("net.Listen: %v", err)
		}
		defer func() { _ = ln.Close() }()

		platCloses := 0
		runDone := make(chan struct{})
		sb := &Sandbox{
			cfg: Config{
				GPU:                GPUConfig{Mode: GPUVenus},
				ControlListener:    ln,
				CheckpointListener: ln,
			},
			gpu:        &gpuHost{},
			runStarted: true,
			runDone:    runDone,
			runMemFile: mf,
			plat: memoryLifetimePlatform{close: func() error {
				platCloses++
				return nil
			}},
		}
		sb.initControlState()

		if err := sb.Close(); err == nil || !strings.Contains(err.Error(), "did not stop") {
			t.Fatalf("first Close = %v, want stop-timeout error", err)
		}
		if platCloses != 0 {
			t.Fatalf("platform closed %d times after timeout, want 0", platCloses)
		}
		if !mf.IsBackingOpen() {
			t.Fatal("MemoryFile destroyed while guest kernel is still running")
		}
		if _, acceptErr := ln.Accept(); !errors.Is(acceptErr, net.ErrClosed) {
			t.Fatalf("control listener Accept after timed-out Close = %v, want net.ErrClosed", acceptErr)
		}
		if err := sb.Checkpoint(context.Background(), CheckpointOptions{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Checkpoint after timed-out Close = %v, want ErrInvalidConfig", err)
		}

		close(runDone)
		if err := sb.Close(); err != nil {
			t.Fatalf("retry Close after kernel exit = %v, want nil", err)
		}
		synctest.Wait()
		if platCloses != 1 {
			t.Fatalf("platform closed %d times after retry Close, want 1", platCloses)
		}
		if err := mf.WaitBackingClosed(t.Context()); err != nil {
			t.Fatalf("WaitBackingClosed after retry Close: %v", err)
		}
		if _, statErr := backing.Stat(); statErr == nil {
			t.Fatal("backing file remains open after retry Close")
		}
	})
}

// TestClosePausedSandboxWithGPUHostStopsKernel boots a live guest kernel,
// pauses it, and closes it through the GPU shutdown path without needing the
// external C renderer binary. It proves Close unpauses before killing and
// tears down the platform and backing memory without timing out.
func TestClosePausedSandboxWithGPUHostStopsKernel(t *testing.T) {
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "ready.txt"), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdinR, stdinW := net.Pipe()
	defer func() { _ = stdinR.Close() }()
	defer func() { _ = stdinW.Close() }()

	stdout := newNotifyBuffer()
	cfg := newCheckpointTestConfig(t, t.TempDir())
	cfg.OCILayerTars = [][]byte{layer}
	cfg.Mounts = []Mount{{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"}}
	cfg.Argv = []string{"/bin/cat", "/mnt/host/ready.txt", "/proc/self/fd/0"}
	cfg.Stdin = stdinR
	cfg.Stdout = stdout

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })
	mf := sb.memFile
	backing := mf.File()

	type runOutcome struct {
		code int
		err  error
	}
	runCh := make(chan runOutcome, 1)
	go func() {
		code, rErr := sb.Run(context.Background())
		runCh <- runOutcome{code: code, err: rErr}
	}()

	stdout.waitForSubstring(t, "ready\n", 15*time.Second)

	sb.mu.Lock()
	sb.gpu = &gpuHost{}
	sb.mu.Unlock()

	if err := sb.Pause(context.Background(), true); err != nil {
		t.Fatalf("Pause: %v", err)
	}

	closeStart := time.Now()
	closeErr := sb.Close()
	closeElapsed := time.Since(closeStart)
	if closeErr != nil {
		t.Fatalf("Close paused sandbox: %v", closeErr)
	}
	if closeElapsed >= 15*time.Second {
		t.Fatalf("Close paused sandbox took %v, want < 15s", closeElapsed)
	}

	out := <-runCh
	wantCode := 128 + int(linux.SIGKILL)
	if out.err != nil || out.code != wantCode {
		t.Fatalf("Run after Close = (%d, %v), want (%d, nil)", out.code, out.err, wantCode)
	}
	assertBackingClosedAfterTeardown(t, "paused-gpu", mf, backing)
}
