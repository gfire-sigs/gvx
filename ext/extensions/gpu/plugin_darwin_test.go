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

//go:build darwin && arm64

package gpu

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gpurender "z.gfire.dev/gvx/ext/extensions/gpu/client"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/exttest"
)

func requireRealRenderer(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(gpurender.EnvRenderer))
	if path == "" {
		t.Skipf("set %s to a built gvx-gpu-renderer binary to run live GPU sandbox tests", gpurender.EnvRenderer)
	}
	exttest.RequireHardwareHypervisor(t)
	return path
}

func buildGPUProbeELF(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling gpuprobe")
	}
	outPath := filepath.Join(t.TempDir(), "gpuprobe")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, "./gpuprobe")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build ./gpuprobe failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read gpuprobe ELF: %v", err)
	}
	return data
}

func TestGPUSandboxRunsVenusAndRefusesCheckpoint(t *testing.T) {
	renderer := requireRealRenderer(t)
	probeELF := buildGPUProbeELF(t)
	layer := exttest.BuildLayerTar(t, exttest.GuestFile{
		Name: "bin/gpuprobe",
		Data: probeELF,
		Mode: 0o755,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            gvx.PlatformHVF,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		OCILayerTars:        [][]byte{layer},
		Argv:                []string{"/bin/gpuprobe"},
		Stdout:              &stdout,
		Stderr:              &stderr,
		DisableHostLockdown: true,
		Extensions: []gvx.Extension{
			NewExtension(Options{
				Mode:         ModeVenus,
				RendererPath: renderer,
			}),
		},
	})
	if err != nil {
		t.Fatalf("gvx.New with GPU extension: %v", err)
	}
	defer func() {
		if cerr := sb.Close(); cerr != nil {
			t.Errorf("Sandbox.Close: %v", cerr)
		}
	}()

	if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{}); !errors.Is(err, gvx.ErrCheckpointExtensionUnsupported) {
		t.Fatalf("Checkpoint with GPU extension err = %v, want ErrCheckpointExtensionUnsupported", err)
	}

	code, err := sb.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("Sandbox.Run = (%d, %v)\nstdout:\n%s\nstderr:\n%s", code, err, stdout.String(), stderr.String())
	}
}
