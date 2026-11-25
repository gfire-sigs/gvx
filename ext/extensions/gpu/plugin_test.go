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

package gpu_test

import (
	"context"
	"errors"
	"flag"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/ext/extensions/gpu"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/exttest"
	"z.gfire.dev/gvx/pkg/rungvx"
)

func TestCLIPluginFlagsAndValidation(t *testing.T) {
	var _ rungvx.CLIPlugin = (*gpu.CLIPlugin)(nil)

	p := gpu.NewCLIPlugin()
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
	ext := cfg.Extensions[0].(*gpu.Extension)
	if ext.Options().Mode != gpu.ModeVenus || ext.Options().MemoryLimitBytes != 512<<20 {
		t.Fatalf("options = %+v, want venus / 512MiB", ext.Options())
	}
	if err := ext.Validate(gvx.ValidationEnv{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}); err != nil {
		t.Fatalf("Validate(normal) err = %v, want nil", err)
	}
	if err := ext.Validate(gvx.ValidationEnv{HasCheckpoint: true}); !errors.Is(err, gvx.ErrCheckpointExtensionUnsupported) {
		t.Fatalf("Validate(HasCheckpoint) err = %v, want ErrCheckpointExtensionUnsupported", err)
	}
	if _, err := ext.OpenPreLockdown(context.Background(), gvx.PreLockdownEnv{}); !errors.Is(err, gpu.ErrRendererUnavailable) {
		t.Fatalf("OpenPreLockdown err = %v, want ErrRendererUnavailable", err)
	}
}

func TestCLIPluginRejectsInvalidModeAndOrphanFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-gpu=metal"},
		{"-gpu-memory-limit=512m"},
		{"-gpu=venus", "-gpu-memory-limit=bogus"},
	} {
		p := gpu.NewCLIPlugin()
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
