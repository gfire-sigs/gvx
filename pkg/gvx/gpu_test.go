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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigGPUParseMode(t *testing.T) {
	if got := GPUOff.String(); got != "off" {
		t.Errorf("GPUOff.String() = %q, want %q", got, "off")
	}
	if got := GPUVenus.String(); got != "venus" {
		t.Errorf("GPUVenus.String() = %q, want %q", got, "venus")
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
		{"reserved virgl", "virgl", "", "reserved"},
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
			name:    "venus with checkpoint listener",
			cfg:     Config{Platform: PlatformAuto, GPU: GPUConfig{Mode: GPUVenus}, CheckpointListener: new(net.TCPListener)},
			goos:    "darwin",
			goarch:  "arm64",
			macOS:   "27.2.1",
			wantErr: "checkpoint",
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
