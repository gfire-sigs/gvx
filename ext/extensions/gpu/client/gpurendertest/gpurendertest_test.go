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

package gpurendertest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/ext/extensions/gpu/client"
)

type recordingTB struct {
	testing.TB
	fatals []string
	skips  []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Fatal(args ...any) {
	r.fatals = append(r.fatals, fmt.Sprint(args...))
}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func (r *recordingTB) Skip(args ...any) {
	r.skips = append(r.skips, fmt.Sprint(args...))
}

func (r *recordingTB) Skipf(format string, args ...any) {
	r.skips = append(r.skips, fmt.Sprintf(format, args...))
}

func (r *recordingTB) FailNow() {
	r.fatals = append(r.fatals, "FailNow")
}

func (r *recordingTB) SkipNow() {
	r.skips = append(r.skips, "SkipNow")
}

func TestPathFailsWhenConfiguredBinaryIsMissing(t *testing.T) {
	t.Setenv(gpurender.EnvRenderer, filepath.Join(t.TempDir(), "absent"))
	rec := &recordingTB{TB: t}

	got := Path(rec)
	if got != "" {
		t.Fatalf("Path() = %q, want empty string", got)
	}

	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if len(rec.fatals) == 0 {
			t.Fatalf("expected Fatal on missing configured binary, got fatals=%v skips=%v", rec.fatals, rec.skips)
		}
		if len(rec.skips) != 0 {
			t.Fatalf("expected no Skip on missing configured binary, got skips=%v", rec.skips)
		}
		return
	}

	if len(rec.skips) == 0 {
		t.Fatalf("expected Skip on %s/%s, got fatals=%v skips=%v", runtime.GOOS, runtime.GOARCH, rec.fatals, rec.skips)
	}
	if len(rec.fatals) != 0 {
		t.Fatalf("expected no Fatal on %s/%s, got fatals=%v", runtime.GOOS, runtime.GOARCH, rec.fatals)
	}
}

func TestNewFailsWhenConfiguredBinaryIsBroken(t *testing.T) {
	broken := filepath.Join(t.TempDir(), "broken-renderer")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\necho broken >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatalf("write %s: %v", broken, err)
	}
	t.Setenv(gpurender.EnvRenderer, broken)

	rec := &recordingTB{TB: t}
	got := New(rec)
	if got != nil {
		_ = got.Close()
		t.Fatal("New() returned non-nil client for broken binary")
	}

	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if len(rec.fatals) == 0 {
			t.Fatalf("expected Fatal on broken configured binary, got fatals=%v skips=%v", rec.fatals, rec.skips)
		}
		if len(rec.skips) != 0 {
			t.Fatalf("expected no Skip on broken configured binary, got skips=%v", rec.skips)
		}
		return
	}

	if len(rec.skips) == 0 {
		t.Fatalf("expected Skip on %s/%s, got fatals=%v skips=%v", runtime.GOOS, runtime.GOARCH, rec.fatals, rec.skips)
	}
	if len(rec.fatals) != 0 {
		t.Fatalf("expected no Fatal on %s/%s, got fatals=%v", runtime.GOOS, runtime.GOARCH, rec.fatals)
	}
}
