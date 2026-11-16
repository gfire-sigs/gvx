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
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

type memoryLifetimePlatform struct {
	platform.Platform
	close func() error
}

func (p memoryLifetimePlatform) Close() error { return p.close() }

func (p memoryLifetimePlatform) UserAddressHoles() []hostarch.AddrRange {
	if hp, ok := p.Platform.(platform.AddressHolePlatform); ok {
		return hp.UserAddressHoles()
	}
	return nil
}

func (p memoryLifetimePlatform) GuestFeatureSet(host cpuid.FeatureSet) cpuid.FeatureSet {
	if g, ok := p.Platform.(guestFeatureSetter); ok {
		return g.GuestFeatureSet(host)
	}
	return host
}

func TestSandboxCloseKeepsBackingUntilPlatformCloses(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		name := "pending"
		if consumed {
			name = "consumed"
		}
		t.Run(name, func(t *testing.T) {
			testSandboxBackingLifetime(t, consumed, nil)
		})
		t.Run(name+"/platform_failure", func(t *testing.T) {
			testSandboxBackingLifetime(t, consumed, errors.New("partition teardown failed"))
		})
	}
}

func testSandboxBackingLifetime(t *testing.T, consumed bool, closeErr error) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		mf, err := createKernelMemoryFile(0)
		if err != nil {
			t.Fatal(err)
		}
		backing := mf.File()
		closes := 0
		sb := &Sandbox{
			memFile: mf,
			plat: memoryLifetimePlatform{close: func() error {
				closes++
				synctest.Wait()
				if _, err := backing.Stat(); err != nil {
					t.Errorf("backing file closed before platform teardown: %v", err)
				}
				return closeErr
			}},
		}
		if consumed {
			// Exercise a sandbox whose Run path already claimed memFile.
			_ = sb.claimRunMemFileForTest()
		}
		if closeErr != nil {
			defer mf.Destroy()
		}
		if err := sb.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("Close = %v, want %v", err, closeErr)
		}
		synctest.Wait()
		_, statErr := backing.Stat()
		if closeErr == nil && statErr == nil {
			t.Error("backing file remains open after successful platform teardown")
		}
		if closeErr != nil && statErr != nil {
			t.Errorf("backing file closed after failed platform teardown: %v", statErr)
		}
		if err := sb.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("second Close = %v, want %v", err, closeErr)
		}
		if closes != 1 {
			t.Errorf("platform closed %d times, want 1", closes)
		}
	})
}

func (s *Sandbox) claimRunMemFileForTest() *os.File {
	if s.memFile == nil {
		return nil
	}
	f := s.memFile.File()
	s.memFile, s.runMemFile = nil, s.memFile
	return f
}

func waitForClosedFile(t *testing.T, what string, f *os.File) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := f.Stat(); err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s backing file remains open after Close", what)
}

func TestSandboxRunAndRestoreKeepBackingUntilClose(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(hostDir, "ready.txt"), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ckptDir := filepath.Join(t.TempDir(), "bundle")
	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout1 := newNotifyBuffer()
	var stderr1 bytes.Buffer
	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.CheckpointDir = ckptDir
	cfg.Mounts = []Mount{{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"}}
	cfg.Argv = []string{"/bin/cat", "/mnt/host/ready.txt", "/proc/self/fd/0"}
	cfg.Stdin = stdinR
	cfg.Stdout = stdout1
	cfg.Stderr = &stderr1

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	freshBacking := sb.memFile.File()
	innerFreshPlat := sb.plat
	var freshCloseSawOpen atomic.Bool
	sb.plat = memoryLifetimePlatform{
		Platform: innerFreshPlat,
		close: func() error {
			runtime.Gosched()
			if _, statErr := freshBacking.Stat(); statErr != nil {
				t.Errorf("fresh backing file closed before platform teardown: %v", statErr)
			} else {
				freshCloseSawOpen.Store(true)
			}
			if closer, ok := innerFreshPlat.(io.Closer); ok {
				return closer.Close()
			}
			return nil
		},
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

	stdout1.waitForSubstring(t, "ready\n", 15*time.Second)
	if err := sb.Checkpoint(context.Background(), CheckpointOptions{}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	out1 := <-runCh
	if out1.err != nil || out1.code != 0 {
		t.Fatalf("fresh Run = (%d, %v), stderr=%q", out1.code, out1.err, stderr1.String())
	}
	// Let any premature Destroy goroutine run before Close starts.
	time.Sleep(15 * time.Millisecond)
	if _, err := freshBacking.Stat(); err != nil {
		t.Fatalf("fresh backing file closed when Run returned, before Close: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("fresh Close: %v", err)
	}
	if !freshCloseSawOpen.Load() {
		t.Fatal("fresh platform Close did not observe an open backing file")
	}
	waitForClosedFile(t, "fresh", freshBacking)

	stdin2R, stdin2W := io.Pipe()
	defer stdin2R.Close()
	go func() {
		_, _ = stdin2W.Write([]byte("resumed\n"))
		_ = stdin2W.Close()
	}()
	var stdout2, stderr2 bytes.Buffer
	restoreCfg := newCheckpointTestConfig(t, cacheDir)
	restoreCfg.Mounts = []Mount{{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"}}
	restoreCfg.Stdin = stdin2R
	restoreCfg.Stdout = &stdout2
	restoreCfg.Stderr = &stderr2

	restoredSB, err := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	restoredBacking := restoredSB.memFile.File()
	innerRestoredPlat := restoredSB.plat
	var restoredCloseSawOpen atomic.Bool
	restoredSB.plat = memoryLifetimePlatform{
		Platform: innerRestoredPlat,
		close: func() error {
			runtime.Gosched()
			if _, statErr := restoredBacking.Stat(); statErr != nil {
				t.Errorf("restored backing file closed before platform teardown: %v", statErr)
			} else {
				restoredCloseSawOpen.Store(true)
			}
			if closer, ok := innerRestoredPlat.(io.Closer); ok {
				return closer.Close()
			}
			return nil
		},
	}

	code2, err := restoredSB.Run(context.Background())
	if err != nil || code2 != 0 {
		_ = restoredSB.Close()
		t.Fatalf("restored Run = (%d, %v), stderr=%q", code2, err, stderr2.String())
	}
	time.Sleep(15 * time.Millisecond)
	if _, err := restoredBacking.Stat(); err != nil {
		_ = restoredSB.Close()
		t.Fatalf("restored backing file closed when Run returned, before Close: %v", err)
	}
	if err := restoredSB.Close(); err != nil {
		t.Fatalf("restored Close: %v", err)
	}
	if !restoredCloseSawOpen.Load() {
		t.Fatal("restored platform Close did not observe an open backing file")
	}
	waitForClosedFile(t, "restored", restoredBacking)
	if got := stdout2.String(); got != "resumed\n" {
		t.Fatalf("restored stdout = %q, want %q", got, "resumed\n")
	}
}
