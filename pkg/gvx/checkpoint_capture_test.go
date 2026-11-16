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
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

type pullErrorPlatform struct {
	platform.Platform
	pullErr *atomic.Pointer[error]
}

func (p pullErrorPlatform) NewContext(ctx gvcontext.Context) platform.Context {
	return pullErrorContext{
		Context: p.Platform.NewContext(ctx),
		pullErr: p.pullErr,
	}
}

func (p pullErrorPlatform) Close() error {
	if closer, ok := p.Platform.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (p pullErrorPlatform) UserAddressHoles() []hostarch.AddrRange {
	if hp, ok := p.Platform.(platform.AddressHolePlatform); ok {
		return hp.UserAddressHoles()
	}
	return nil
}

func (p pullErrorPlatform) GuestFeatureSet(host cpuid.FeatureSet) cpuid.FeatureSet {
	if g, ok := p.Platform.(guestFeatureSetter); ok {
		return g.GuestFeatureSet(host)
	}
	return host
}

type pullErrorContext struct {
	platform.Context
	pullErr *atomic.Pointer[error]
}

func (c pullErrorContext) PullFullState(as platform.AddressSpace, ac *arch.Context64) error {
	if errPtr := c.pullErr.Swap(nil); errPtr != nil && *errPtr != nil {
		return platform.NewIOContextError(*errPtr)
	}
	return c.Context.PullFullState(as, ac)
}

func TestCheckpointPropagatesTaskStateCaptureError(t *testing.T) {
	cacheDir := t.TempDir()
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "before.txt"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ckptDir := filepath.Join(t.TempDir(), "bundle")

	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout := newNotifyBuffer()
	var stderr bytes.Buffer
	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.CheckpointDir = ckptDir
	cfg.Mounts = []Mount{{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"}}
	cfg.Argv = []string{"/bin/cat", "/mnt/host/before.txt", "/proc/self/fd/0"}
	cfg.Stdin = stdinR
	cfg.Stdout = stdout
	cfg.Stderr = &stderr

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	var pullErr atomic.Pointer[error]
	sb.plat = pullErrorPlatform{
		Platform: sb.plat,
		pullErr:  &pullErr,
	}

	type runOutcome struct {
		code int
		err  error
	}
	runCh := make(chan runOutcome, 1)
	go func() {
		code, rErr := sb.Run(context.Background())
		runCh <- runOutcome{code: code, err: rErr}
	}()

	stdout.waitForSubstring(t, "before\n", 15*time.Second)

	wantErr := errors.New("simulated platform register read failure")
	pullErr.Store(&wantErr)

	ckptErr := sb.Checkpoint(context.Background(), CheckpointOptions{})
	var ctxErr *platform.ContextError
	if !errors.Is(ckptErr, wantErr) || !errors.As(ckptErr, &ctxErr) {
		t.Fatalf("Checkpoint = %v, want *platform.ContextError wrapping %v", ckptErr, wantErr)
	}

	restoreCfg := newCheckpointTestConfig(t, cacheDir)
	restoreCfg.Mounts = []Mount{{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"}}
	if brokenSB, rErr := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir}); !errors.Is(rErr, ErrCheckpointManifest) {
		if brokenSB != nil {
			_ = brokenSB.Close()
		}
		t.Fatalf("Restore from aborted checkpoint = %v, want %v", rErr, ErrCheckpointManifest)
	}

	if _, err := stdinW.Write([]byte("after-failed-ckpt\n")); err != nil {
		t.Fatalf("write stdin after failed checkpoint: %v", err)
	}
	_ = stdinW.Close()

	out := <-runCh
	if out.err != nil || out.code != 0 {
		t.Fatalf("guest Run after failed checkpoint = (%d, %v), stderr=%q", out.code, out.err, stderr.String())
	}
	if got := stdout.String(); got != "before\nafter-failed-ckpt\n" {
		t.Fatalf("guest stdout = %q, want %q", got, "before\nafter-failed-ckpt\n")
	}
}
