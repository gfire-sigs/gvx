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

// Package gpurendertest starts the real GPU renderer for tests of any package.
package gpurendertest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/internal/gpurender"
)

const skipBundleMsg = "no GPU renderer bundle: run scripts/gpu/build-renderer.sh or set GVX_GPU_RENDERER"

// Path returns the renderer executable for a test. It uses
// gpurender.EnvRenderer when set and fails the test when that path is not a
// regular executable file. Otherwise it walks up from the working directory
// to the directory with go.mod and uses
// build/gpu/gvx-gpu-renderer/bin/gvx-gpu-renderer there. It skips the test
// when no bundle exists, and on every OS other than darwin/arm64.
func Path(t testing.TB) string {
	t.Helper()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("GPU renderer runs only on darwin/arm64")
		return ""
	}
	if env := os.Getenv(gpurender.EnvRenderer); env != "" {
		p, err := gpurender.Locate(env)
		if err != nil {
			t.Fatalf("configured %s=%q: %v", gpurender.EnvRenderer, env, err)
			return ""
		}
		return p
	}
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for {
			if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
				cand := filepath.Join(dir, "build", "gpu", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer")
				if p, lerr := gpurender.Locate(cand); lerr == nil {
					return p
				}
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	t.Skip(skipBundleMsg)
	return ""
}

// New starts the renderer with default options and closes it at cleanup.
func New(t testing.TB) *gpurender.Client {
	t.Helper()
	return NewWithOptions(t, gpurender.Options{})
}

// NewWithOptions starts the renderer with opts and closes it at cleanup.
// An empty opts.Path is filled by Path, and a nil opts.Log logs through t.
// A start failure fails the test.
func NewWithOptions(t testing.TB, opts gpurender.Options) *gpurender.Client {
	t.Helper()
	if opts.Path == "" {
		opts.Path = Path(t)
		if opts.Path == "" {
			return nil
		}
	}
	if opts.Log == nil {
		opts.Log = func(line string) { t.Log("renderer: " + line) }
	}
	c, err := gpurender.Start(context.Background(), opts)
	if err != nil {
		t.Fatalf("start GPU renderer: %v", err)
		return nil
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
