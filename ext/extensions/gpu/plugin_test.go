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

package gpu

import (
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/exttest"
	"z.gfire.dev/gvx/pkg/rungvx"
)

func TestCLIPluginFlagsAndValidation(t *testing.T) {
	var _ rungvx.CLIPlugin = (*CLIPlugin)(nil)

	p := NewCLIPlugin()
	if p.Name() != "gpu" || p.BuildSummary() != "modes=venus,virgl" {
		t.Fatalf("metadata = (%q, %q), want (gpu, modes=venus,virgl)", p.Name(), p.BuildSummary())
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	p.RegisterFlags(fs)
	if err := fs.Parse([]string{"-gpu=venus", "-gpu-memory-limit=512m"}); err != nil {
		t.Fatalf("fs.Parse: %v", err)
	}
	var cfg gvx.Config
	if err := p.ApplyConfig(&cfg); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if len(cfg.Extensions) != 1 || cfg.Extensions[0].Name() != "gpu" {
		t.Fatalf("cfg.Extensions = %v, want 1 gpu extension", cfg.Extensions)
	}
	ext := cfg.Extensions[0].(*Extension)
	ext.macOSVersion = func() string { return "26.0" }
	if ext.Options().Mode != ModeVenus || ext.Options().MemoryLimitBytes != 512<<20 {
		t.Fatalf("options = %+v, want venus / 512MiB", ext.Options())
	}

	// Valid darwin/arm64 macOS 26+ hvf environment passes validation.
	if err := ext.Validate(gvx.ValidationEnv{GOOS: "darwin", GOARCH: "arm64", Platform: gvx.PlatformHVF}); err != nil {
		t.Fatalf("Validate(darwin/arm64 hvf) err = %v, want nil", err)
	}
	// Checkpoint and restore fail closed with ErrCheckpointExtensionUnsupported.
	if err := ext.Validate(gvx.ValidationEnv{GOOS: "darwin", GOARCH: "arm64", HasCheckpoint: true}); !errors.Is(err, gvx.ErrCheckpointExtensionUnsupported) {
		t.Fatalf("Validate(HasCheckpoint) err = %v, want ErrCheckpointExtensionUnsupported", err)
	}
	if err := ext.Validate(gvx.ValidationEnv{GOOS: "darwin", GOARCH: "arm64", IsRestore: true}); !errors.Is(err, gvx.ErrCheckpointExtensionUnsupported) {
		t.Fatalf("Validate(IsRestore) err = %v, want ErrCheckpointExtensionUnsupported", err)
	}
	// Non-darwin/arm64 or non-hvf platform returns ErrPlatformUnavailable.
	if err := ext.Validate(gvx.ValidationEnv{GOOS: "linux", GOARCH: "amd64"}); !errors.Is(err, gvx.ErrPlatformUnavailable) {
		t.Fatalf("Validate(linux/amd64) err = %v, want ErrPlatformUnavailable", err)
	}
	if err := ext.Validate(gvx.ValidationEnv{GOOS: "darwin", GOARCH: "arm64", Platform: gvx.PlatformSystrap}); !errors.Is(err, gvx.ErrPlatformUnavailable) {
		t.Fatalf("Validate(systrap) err = %v, want ErrPlatformUnavailable", err)
	}
	// macOS below 26 returns ErrPlatformUnavailable.
	ext.macOSVersion = func() string { return "15.4" }
	if err := ext.Validate(gvx.ValidationEnv{GOOS: "darwin", GOARCH: "arm64", Platform: gvx.PlatformHVF}); !errors.Is(err, gvx.ErrPlatformUnavailable) {
		t.Fatalf("Validate(macOS 15.4) err = %v, want ErrPlatformUnavailable", err)
	}

	// OpenPreLockdown rejects non-hvf platforms and missing renderers explicitly.
	if _, err := ext.OpenPreLockdown(context.Background(), gvx.PreLockdownEnv{PlatformName: "systrap"}); !errors.Is(err, gvx.ErrPlatformUnavailable) {
		t.Fatalf("OpenPreLockdown(systrap) err = %v, want ErrPlatformUnavailable", err)
	}
	extMissing := NewExtension(Options{Mode: ModeVenus, RendererPath: "/nonexistent/gvx-gpu-renderer"})
	if _, err := extMissing.OpenPreLockdown(context.Background(), gvx.PreLockdownEnv{PlatformName: "hvf"}); !errors.Is(err, ErrRendererUnavailable) {
		t.Fatalf("OpenPreLockdown(missing renderer) err = %v, want ErrRendererUnavailable", err)
	}
}

func TestCLIPluginRejectsInvalidReservedAndOrphanFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-gpu=metal"},
		{"-gpu=auto"},
		{"-gpu-memory-limit=512m"},
		{"-gpu-renderer=/tmp/renderer"},
		{"-gpu=venus", "-gpu-memory-limit=bogus"},
	} {
		p := NewCLIPlugin()
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		p.RegisterFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("fs.Parse(%v): %v", args, err)
		}
		var cfg gvx.Config
		if err := p.ApplyConfig(&cfg); !errors.Is(err, gvx.ErrInvalidConfig) {
			t.Fatalf("ApplyConfig(%v) err = %v, want ErrInvalidConfig", args, err)
		}
	}
}

func TestEffectiveMemoryLimitCapsAtFourGiBOrQuarterRAM(t *testing.T) {
	if got := effectiveMemoryLimit(512<<20, 64<<30); got != 512<<20 {
		t.Fatalf("explicit limit = %d, want 512MiB", got)
	}
	if got := effectiveMemoryLimit(0, 64<<30); got != defaultMemoryLimit {
		t.Fatalf("64GiB host = %d, want 4GiB", got)
	}
	if got := effectiveMemoryLimit(0, 8<<30); got != 2<<30 {
		t.Fatalf("8GiB host = %d, want 2GiB", got)
	}
	if got := effectiveMemoryLimit(0, 0); got != defaultMemoryLimit {
		t.Fatalf("unknown RAM = %d, want 4GiB", got)
	}
}

func TestExtTestHarnessRunsGuestInsideExtModule(t *testing.T) {
	exttest.RequireGuestBackend(t)

	probeELF := exttest.BuildGuestGoELF(t, `package main
import "fmt"
func main() { fmt.Println("EXTTEST_OK") }
`)
	layer := exttest.BuildLayerTar(t, exttest.GuestFile{
		Name: "bin/probe",
		Data: probeELF,
		Mode: 0o755,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := exttest.RunSandbox(t, ctx, gvx.Config{
		OCILayerTars: [][]byte{layer},
		Argv:         []string{"/bin/probe"},
	})
	if err != nil || res.ExitCode != 0 || !strings.Contains(res.Stdout, "EXTTEST_OK") {
		t.Fatalf("RunSandbox = (%+v, %v), want exit 0 with EXTTEST_OK", res, err)
	}
}
