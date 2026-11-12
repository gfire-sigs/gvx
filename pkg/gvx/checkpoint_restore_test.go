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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
)

func requireCheckpointGuestBackend(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		hvtest.Require(t)
		return
	}
	if runtime.GOOS == "windows" && !hvtest.Available() {
		systraptest.Require(t)
	}
}

func newCheckpointTestConfig(t *testing.T, cacheDir string) Config {
	t.Helper()
	requireCheckpointGuestBackend(t)
	return Config{
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		NetworkMode:            NetModeNone,
		OCICacheDir:            cacheDir,
		DisableHostLockdown:    true,
	}
}

type notifyBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	changed chan struct{}
}

func newNotifyBuffer() *notifyBuffer {
	return &notifyBuffer{changed: make(chan struct{}, 1)}
}

func (b *notifyBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	b.mu.Unlock()
	select {
	case b.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (b *notifyBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *notifyBuffer) waitForSubstring(t *testing.T, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if strings.Contains(b.String(), want) {
			return
		}
		select {
		case <-b.changed:
		case <-deadline.C:
			t.Fatalf("timed out waiting for stdout %q (got %q)", want, b.String())
		}
	}
}

func seedExt4VolumeFile(t *testing.T, cacheDir, volumeImagePath, guestFilePath, content string) {
	t.Helper()
	writeELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, guestFilePath, content)
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64: %v", err)
	}
	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.ELFBytes = writeELF
	cfg.Mounts = []Mount{
		{
			Kind:      MountVolume,
			ImagePath: volumeImagePath,
			Driver:    DriverExt4lite,
			GuestPath: filepath.ToSlash(filepath.Dir(guestFilePath)),
		},
	}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf
	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("seed volume New: %v", err)
	}
	code, runErr := sb.Run(context.Background())
	closeErr := sb.Close()
	if runErr != nil || closeErr != nil || code != 0 {
		t.Fatalf("seed volume Run=(%d, %v) Close=%v stderr=%q", code, runErr, closeErr, errBuf.String())
	}
}

func TestCheckpointAndRestoreStopAndResume(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(hostDir, "before.txt"), []byte("before-from-hostfs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	volImage := filepath.Join(t.TempDir(), "vol.ext4")
	seedExt4VolumeFile(t, cacheDir, volImage, "/mnt/vol/after.txt", "after-from-ext4\n")

	ckptDir := filepath.Join(t.TempDir(), "bundle")
	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout1 := newNotifyBuffer()
	var stderr1 syncBuffer

	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.CheckpointDir = ckptDir
	cfg.Mounts = []Mount{
		{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"},
		{Kind: MountVolume, ImagePath: volImage, Driver: DriverExt4lite, GuestPath: "/mnt/vol"},
	}
	cfg.Argv = []string{"/bin/cat", "/mnt/host/before.txt", "/proc/self/fd/0", "/mnt/vol/after.txt"}
	cfg.Stdin = stdinR
	cfg.Stdout = stdout1
	cfg.Stderr = &stderr1

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	type runResult struct {
		code int
		err  error
	}
	runCh := make(chan runResult, 1)
	go func() {
		code, rErr := sb.Run(context.Background())
		runCh <- runResult{code: code, err: rErr}
	}()

	stdout1.waitForSubstring(t, "before-from-hostfs\n", 15*time.Second)

	if err := sb.Checkpoint(context.Background(), CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint(LeaveRunning=false): %v", err)
	}

	res1 := <-runCh
	if res1.err != nil || res1.code != 0 {
		t.Fatalf("stopped sandbox Run = (%d, %v), want (0, nil); stderr=%q", res1.code, res1.err, stderr1.String())
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("stopped sandbox Close: %v", err)
	}

	for _, name := range []string{
		checkpointManifestFileName,
		checkpointStateFileName,
		checkpointPagesMetaFileName,
		checkpointPagesFileName,
	} {
		st, statErr := os.Stat(filepath.Join(ckptDir, name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if st.Size() == 0 {
			t.Fatalf("checkpoint file %s is empty", name)
		}
	}

	manifest, err := readAndParseManifest(ckptDir)
	if err != nil {
		t.Fatalf("readAndParseManifest: %v", err)
	}
	if manifest.Version != CheckpointManifestVersion {
		t.Fatalf("manifest.Version = %d, want %d", manifest.Version, CheckpointManifestVersion)
	}
	if len(manifest.LayerDigests) != 1 {
		t.Fatalf("manifest.LayerDigests = %v, want 1 digest", manifest.LayerDigests)
	}
	if len(manifest.Mounts) != 2 {
		t.Fatalf("manifest.Mounts = %v, want 2 mounts", manifest.Mounts)
	}

	var stdout2, stderr2 bytes.Buffer
	restoreCfg := newCheckpointTestConfig(t, cacheDir)
	restoreCfg.OCILayerTars = [][]byte{layer}
	restoreCfg.Mounts = []Mount{
		{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"},
		{Kind: MountVolume, ImagePath: volImage, Driver: DriverExt4lite, GuestPath: "/mnt/vol"},
	}
	restoreCfg.Stdin = strings.NewReader("resumed-from-stdin\n")
	restoreCfg.Stdout = &stdout2
	restoreCfg.Stderr = &stderr2

	restoredSB, err := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	defer func() {
		if cErr := restoredSB.Close(); cErr != nil {
			t.Errorf("restoredSB.Close: %v", cErr)
		}
	}()

	code2, err := restoredSB.Run(context.Background())
	if err != nil || code2 != 0 {
		t.Fatalf("restoredSB.Run = (%d, %v), want (0, nil); stderr=%q", code2, err, stderr2.String())
	}
	wantOut2 := "resumed-from-stdin\nafter-from-ext4\n"
	if stdout2.String() != wantOut2 {
		t.Fatalf("restored stdout = %q, want %q", stdout2.String(), wantOut2)
	}
}

func TestCheckpointLeaveRunningAndRestore(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(hostDir, "before.txt"), []byte("before-live\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "after.txt"), []byte("after-live\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ckptDir := filepath.Join(t.TempDir(), "bundle-live")
	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout1 := newNotifyBuffer()
	var stderr1 syncBuffer

	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.CheckpointDir = ckptDir
	cfg.Mounts = []Mount{
		{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"},
	}
	cfg.Argv = []string{"/bin/cat", "/mnt/host/before.txt", "/proc/self/fd/0", "/mnt/host/after.txt"}
	cfg.Stdin = stdinR
	cfg.Stdout = stdout1
	cfg.Stderr = &stderr1

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer sb.Close()

	type runResult struct {
		code int
		err  error
	}
	runCh := make(chan runResult, 1)
	go func() {
		code, rErr := sb.Run(context.Background())
		runCh <- runResult{code: code, err: rErr}
	}()

	stdout1.waitForSubstring(t, "before-live\n", 15*time.Second)

	if err := sb.Checkpoint(context.Background(), CheckpointOptions{LeaveRunning: true}); err != nil {
		t.Fatalf("Checkpoint(LeaveRunning=true): %v", err)
	}

	go func() {
		_, _ = io.WriteString(stdinW, "original-continues\n")
		_ = stdinW.Close()
	}()

	res1 := <-runCh
	if res1.err != nil || res1.code != 0 {
		t.Fatalf("original sandbox Run = (%d, %v), want (0, nil); stderr=%q", res1.code, res1.err, stderr1.String())
	}
	wantOut1 := "before-live\noriginal-continues\nafter-live\n"
	if stdout1.String() != wantOut1 {
		t.Fatalf("original stdout = %q, want %q", stdout1.String(), wantOut1)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("original Close: %v", err)
	}

	var stdout2, stderr2 bytes.Buffer
	restoreCfg := newCheckpointTestConfig(t, cacheDir)
	restoreCfg.OCILayerTars = [][]byte{layer}
	restoreCfg.Mounts = []Mount{
		{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"},
	}
	restoreCfg.Stdin = strings.NewReader("restored-continues\n")
	restoreCfg.Stdout = &stdout2
	restoreCfg.Stderr = &stderr2

	restoredSB, err := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	defer func() {
		if cErr := restoredSB.Close(); cErr != nil {
			t.Errorf("restoredSB.Close: %v", cErr)
		}
	}()

	code2, err := restoredSB.Run(context.Background())
	if err != nil || code2 != 0 {
		t.Fatalf("restoredSB.Run = (%d, %v), want (0, nil); stderr=%q", code2, err, stderr2.String())
	}
	wantOut2 := "restored-continues\nafter-live\n"
	if stdout2.String() != wantOut2 {
		t.Fatalf("restored stdout = %q, want %q", stdout2.String(), wantOut2)
	}
}

func TestCheckpointAndRestoreTwoSandboxesConcurrent(t *testing.T) {
	requireCheckpointGuestBackend(t)
	cacheDir := t.TempDir()
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	const numSandboxes = 2
	var wg sync.WaitGroup
	errs := make(chan error, numSandboxes)

	for idx := range numSandboxes {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("sandbox-%d", id)
			hostDir := t.TempDir()
			beforeMarker := fmt.Sprintf("before-%d\n", id)
			afterMarker := fmt.Sprintf("after-%d\n", id)
			if wErr := os.WriteFile(filepath.Join(hostDir, "before.txt"), []byte(beforeMarker), 0o600); wErr != nil {
				errs <- fmt.Errorf("%s write before.txt: %w", name, wErr)
				return
			}
			if wErr := os.WriteFile(filepath.Join(hostDir, "after.txt"), []byte(afterMarker), 0o600); wErr != nil {
				errs <- fmt.Errorf("%s write after.txt: %w", name, wErr)
				return
			}

			ckptDir := filepath.Join(t.TempDir(), fmt.Sprintf("bundle-%d", id))
			stdinR, stdinW := net.Pipe()
			defer stdinR.Close()
			defer stdinW.Close()

			stdout1 := newNotifyBuffer()
			var stderr1 syncBuffer

			cfg := Config{
				Name:                   name,
				Platform:               PlatformAuto,
				AllowUnconfinedSystrap: runtime.GOOS == "windows",
				NetworkMode:            NetModeNone,
				OCICacheDir:            cacheDir,
				OCILayerTars:           [][]byte{layer},
				CheckpointDir:          ckptDir,
				DisableHostLockdown:    true,
				Mounts: []Mount{
					{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"},
				},
				Argv:   []string{"/bin/cat", "/mnt/host/before.txt", "/proc/self/fd/0", "/mnt/host/after.txt"},
				Stdin:  stdinR,
				Stdout: stdout1,
				Stderr: &stderr1,
			}

			sb, nErr := New(context.Background(), cfg)
			if nErr != nil {
				errs <- fmt.Errorf("%s New: %w", name, nErr)
				return
			}
			defer sb.Close()

			runDone := make(chan error, 1)
			go func() {
				code, rErr := sb.Run(context.Background())
				if rErr != nil {
					runDone <- rErr
					return
				}
				if code != 0 {
					runDone <- fmt.Errorf("exit code %d", code)
					return
				}
				runDone <- nil
			}()

			deadline := time.NewTimer(20 * time.Second)
			for !strings.Contains(stdout1.String(), beforeMarker) {
				select {
				case <-stdout1.changed:
				case <-deadline.C:
					deadline.Stop()
					errs <- fmt.Errorf("%s timed out waiting for %q (got %q)", name, beforeMarker, stdout1.String())
					return
				}
			}
			deadline.Stop()

			if cErr := sb.Checkpoint(context.Background(), CheckpointOptions{LeaveRunning: false}); cErr != nil {
				errs <- fmt.Errorf("%s Checkpoint: %w", name, cErr)
				return
			}
			if rErr := <-runDone; rErr != nil {
				errs <- fmt.Errorf("%s stopped Run: %w (stderr=%q)", name, rErr, stderr1.String())
				return
			}
			if cErr := sb.Close(); cErr != nil {
				errs <- fmt.Errorf("%s Close: %w", name, cErr)
				return
			}

			resumeInput := fmt.Sprintf("stdin-restored-%d\n", id)
			var stdout2, stderr2 bytes.Buffer
			restoreCfg := Config{
				Name:                   name,
				Platform:               PlatformAuto,
				AllowUnconfinedSystrap: runtime.GOOS == "windows",
				NetworkMode:            NetModeNone,
				OCICacheDir:            cacheDir,
				OCILayerTars:           [][]byte{layer},
				DisableHostLockdown:    true,
				Mounts: []Mount{
					{Kind: MountBind, HostPath: hostDir, GuestPath: "/mnt/host"},
				},
				Stdin:  strings.NewReader(resumeInput),
				Stdout: &stdout2,
				Stderr: &stderr2,
			}

			restoredSB, resErr := Restore(context.Background(), restoreCfg, RestoreOptions{Dir: ckptDir})
			if resErr != nil {
				errs <- fmt.Errorf("%s Restore: %w", name, resErr)
				return
			}
			defer restoredSB.Close()

			code2, run2Err := restoredSB.Run(context.Background())
			if run2Err != nil || code2 != 0 {
				errs <- fmt.Errorf("%s restored Run=(%d, %v) stderr=%q", name, code2, run2Err, stderr2.String())
				return
			}
			wantOut := resumeInput + afterMarker
			if stdout2.String() != wantOut {
				errs <- fmt.Errorf("%s restored stdout=%q, want %q", name, stdout2.String(), wantOut)
				return
			}
		}(idx)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestRestoreManifestValidationRejectsMismatch(t *testing.T) {
	cacheDir := t.TempDir()
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	ckptDir := filepath.Join(t.TempDir(), "bundle-validate")
	for _, name := range []string{
		checkpointStateFileName,
		checkpointPagesMetaFileName,
		checkpointPagesFileName,
	} {
		if err := os.MkdirAll(ckptDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ckptDir, name), []byte("stub"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	baseCfg := newCheckpointTestConfig(t, cacheDir)
	baseCfg.OCILayerTars = [][]byte{layer}
	probeSB, err := New(context.Background(), baseCfg)
	if err != nil {
		t.Fatalf("probe New: %v", err)
	}
	validManifest := probeSB.buildCheckpointManifest()
	if err := probeSB.Close(); err != nil {
		t.Fatalf("probe Close: %v", err)
	}

	writeManifest := func(t *testing.T, m CheckpointManifest) {
		t.Helper()
		b, mErr := json.Marshal(m)
		if mErr != nil {
			t.Fatal(mErr)
		}
		if wErr := os.WriteFile(filepath.Join(ckptDir, checkpointManifestFileName), b, 0o600); wErr != nil {
			t.Fatal(wErr)
		}
	}

	t.Run("layer_digest_mismatch", func(t *testing.T) {
		m := validManifest
		m.LayerDigests = []string{"0000000000000000000000000000000000000000000000000000000000000000"}
		writeManifest(t, m)

		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		_, rErr := Restore(context.Background(), cfg, RestoreOptions{Dir: ckptDir})
		if !errors.Is(rErr, ErrCheckpointManifest) || !strings.Contains(rErr.Error(), "layer digests mismatch") {
			t.Fatalf("Restore error = %v, want ErrCheckpointManifest with layer digests mismatch", rErr)
		}
	})

	t.Run("user_address_holes_mismatch", func(t *testing.T) {
		m := validManifest
		m.UserAddressHoles = []AddrHoleEntry{{Start: 0x1000, End: 0x2000}}
		writeManifest(t, m)

		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		_, rErr := Restore(context.Background(), cfg, RestoreOptions{Dir: ckptDir})
		if !errors.Is(rErr, ErrCheckpointManifest) || !strings.Contains(rErr.Error(), "user address holes mismatch") {
			t.Fatalf("Restore error = %v, want ErrCheckpointManifest with user address holes mismatch", rErr)
		}
	})

	t.Run("version_mismatch", func(t *testing.T) {
		m := validManifest
		m.Version = 99
		writeManifest(t, m)

		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		_, rErr := Restore(context.Background(), cfg, RestoreOptions{Dir: ckptDir})
		if !errors.Is(rErr, ErrCheckpointManifest) || !strings.Contains(rErr.Error(), "unsupported version") {
			t.Fatalf("Restore error = %v, want ErrCheckpointManifest with unsupported version", rErr)
		}
	})
}
