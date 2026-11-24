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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

const volumeCapGuestSource = `package main

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func out(s string) {
	_, _ = os.Stdout.WriteString(s + "\n")
}

func main() {
	out("READY")
	scanner := bufio.NewScanner(os.Stdin)
	var held *os.File
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "create":
			if len(fields) < 3 {
				out("ERR:bad-create")
				continue
			}
			f, err := os.OpenFile(fields[1], os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
			if err != nil {
				out("ERR:" + err.Error())
				continue
			}
			if _, err := f.WriteString(fields[2]); err != nil {
				_ = f.Close()
				out("ERR:" + err.Error())
				continue
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				out("ERR:" + err.Error())
				continue
			}
			_ = f.Close()
			out("CREATED")
		case "open":
			if len(fields) != 2 {
				out("ERR:bad-open")
				continue
			}
			if held != nil {
				_ = held.Close()
				held = nil
			}
			f, err := os.OpenFile(fields[1], os.O_RDWR, 0)
			if err != nil {
				out("ERR:" + err.Error())
				continue
			}
			buf := make([]byte, 64)
			n, err := f.ReadAt(buf, 0)
			if err != nil && !errors.Is(err, os.ErrClosed) && n == 0 {
				_ = f.Close()
				out("ERR:" + err.Error())
				continue
			}
			held = f
			out("OPENED:" + string(buf[:n]))
		case "read":
			if held == nil {
				out("ERR:not-open")
				continue
			}
			buf := make([]byte, 64)
			n, err := held.ReadAt(buf, 0)
			if err != nil && n == 0 {
				out("ERR:" + err.Error())
				continue
			}
			out("READ:" + string(buf[:n]))
		case "close":
			if held != nil {
				_ = held.Close()
				held = nil
			}
			out("CLOSED")
		case "statfs":
			if len(fields) != 2 {
				out("ERR:bad-statfs")
				continue
			}
			var st syscall.Statfs_t
			if err := syscall.Statfs(fields[1], &st); err != nil {
				out("ERR:" + err.Error())
				continue
			}
			out("STATFS:" + strconv.FormatUint(st.Blocks, 10) + ":" + strconv.FormatUint(st.Files, 10))
		case "fill":
			if len(fields) != 3 {
				out("ERR:bad-fill")
				continue
			}
			mib, err := strconv.Atoi(fields[2])
			if err != nil || mib <= 0 {
				out("ERR:bad-mib")
				continue
			}
			f, err := os.OpenFile(fields[1], os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				if errors.Is(err, syscall.ENOSPC) {
					out("ENOSPC")
				} else {
					out("ERR:" + err.Error())
				}
				continue
			}
			var wErr error
			for range mib {
				if _, wErr = f.Write(chunk); wErr != nil {
					break
				}
			}
			if wErr == nil {
				wErr = f.Sync()
			}
			_ = f.Close()
			switch {
			case wErr == nil:
				out("FILLED")
			case errors.Is(wErr, syscall.ENOSPC):
				out("ENOSPC")
			default:
				out("ERR:" + wErr.Error())
			}
		case "unlink":
			if len(fields) != 2 {
				out("ERR:bad-unlink")
				continue
			}
			if err := os.Remove(fields[1]); err != nil {
				out("ERR:" + err.Error())
				continue
			}
			out("UNLINKED")
		case "umount":
			if len(fields) != 2 {
				out("ERR:bad-umount")
				continue
			}
			if err := syscall.Unmount(fields[1], 0); err != nil {
				out("ERR:" + err.Error())
				continue
			}
			out("UMOUNTED")
		case "quit":
			if held != nil {
				_ = held.Close()
			}
			return
		}
	}
}
`

func buildVolumeCapGuestLayer(t *testing.T) ([]byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module volcap\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(volumeCapGuestSource), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "volcap")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build volcap guest ELF: %v\n%s", err, out)
	}
	elfBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/volcap", Data: elfBytes, Mode: 0o755},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "scratch/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	return elfBytes, layer
}

func copyCheckpointBundleDir(t *testing.T, srcDir string) string {
	t.Helper()
	dstDir := t.TempDir()
	for _, name := range []string{
		checkpointManifestFileName,
		checkpointStateFileName,
		checkpointPagesMetaFileName,
		checkpointPagesFileName,
	} {
		data, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dstDir
}

func TestParseMountVolumeSizeAndEphemeral(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want Mount
	}{
		{
			"type=volume,src=data,dst=/v,size=16m",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 16 << 20},
		},
		{
			"src=data,dst=/v,size=64MiB",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 64 << 20},
		},
		{
			"type=volume,src=data,dst=/v,size=16384k",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 16 << 20},
		},
		{
			"type=volume,src=data,dst=/v,size=1g",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 1 << 30},
		},
		{
			"type=volume,src=data,dst=/v,size=64t",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 64 << 40},
		},
		{
			"type=volume,src=data,dst=/v,size=16777216",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 16 << 20},
		},
		{
			"type=volume,src=data,dst=/v,size=33554432b",
			Mount{Kind: MountVolume, VolumeName: "data", GuestPath: "/v", SizeBytes: 32 << 20},
		},
		{
			"type=volume,dst=/scratch,ephemeral",
			Mount{Kind: MountVolume, GuestPath: "/scratch", Ephemeral: true},
		},
		{
			"dst=/scratch,ephemeral,size=32m,driver=ext4lite",
			Mount{Kind: MountVolume, GuestPath: "/scratch", Driver: DriverExt4lite, Ephemeral: true, SizeBytes: 32 << 20},
		},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			got, err := ParseMount(tc.spec)
			if err != nil {
				t.Fatalf("ParseMount(%q) failed: %v", tc.spec, err)
			}
			if got != tc.want {
				t.Fatalf("ParseMount(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}

	for _, spec := range []string{
		"type=volume,src=data,dst=/v,size=0",
		"type=volume,src=data,dst=/v,size=",
		"type=volume,src=data,dst=/v,size",
		"type=volume,src=data,dst=/v,size=-16m",
		"type=volume,src=data,dst=/v,size=8m",
		"type=volume,src=data,dst=/v,size=20m",
		"type=volume,src=data,dst=/v,size=65t",
		"type=volume,src=data,dst=/v,size=16z",
		"type=volume,src=data,dst=/v,size=16m,size=32m",
		"type=volume,dst=/v,ephemeral,ephemeral",
		"type=volume,dst=/v,ephemeral=true",
		"type=volume,dst=/v,ephemeral=false",
		"type=volume,src=data,dst=/v,ephemeral",
		"type=volume,src=,dst=/v,ephemeral",
		"type=volume,dst=/v,ephemeral,readonly",
		"type=volume,dst=/v,ephemeral,ro=true",
		"type=bind,src=/h,dst=/g,size=16m",
		"type=tmpfs,dst=/t,size=16m",
		"type=overlay,src=base,dst=/o,size=16m",
		"type=bind,src=/h,dst=/g,ephemeral",
		"type=tmpfs,dst=/t,ephemeral",
		"type=overlay,src=base,dst=/o,ephemeral",
		"type=volume,src=data,dst=/v,driver=hostfs,size=16m",
		"type=volume,dst=/v,driver=hostfs,ephemeral",
	} {
		if m, err := ParseMount(spec); err == nil {
			t.Errorf("ParseMount(%q) = %+v, want error", spec, m)
		}
	}
}

func TestMountValidationLegacyHostfsSharedROAndOversizedImage(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if _, err := CreateVolume(cacheDir, "legacy-dir", DriverHostfs); err != nil {
		t.Fatalf("CreateVolume(hostfs): %v", err)
	}
	if _, err := CreateVolume(cacheDir, "shared-ro", DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume(ext4lite): %v", err)
	}

	// Legacy directory volume resolving implicitly to hostfs rejects SizeBytes.
	legacyCfg := Config{
		OCICacheDir: cacheDir,
		Mounts: []Mount{
			{Kind: MountVolume, VolumeName: "legacy-dir", GuestPath: "/legacy", SizeBytes: 16 << 20},
		},
	}
	if err := legacyCfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("legacy hostfs volume with SizeBytes normalize() = %v, want ErrInvalidConfig", err)
	}

	// Shared read-only mounts with identical limits succeed; conflicting limits fail.
	sameROCfg := Config{
		OCICacheDir: cacheDir,
		Mounts: []Mount{
			{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro1", ReadOnly: true, SizeBytes: 32 << 20},
			{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro2", ReadOnly: true, SizeBytes: 32 << 20},
		},
	}
	if err := sameROCfg.normalize(); err != nil {
		t.Fatalf("matching shared RO normalize(): %v", err)
	}
	sbSame := NewSandboxForMountTest(sameROCfg)
	if err := OpenMountsForTest(sbSame); err != nil {
		t.Fatalf("OpenMountsForTest(matching shared RO): %v", err)
	}
	if err := CloseMountsForTest(sbSame); err != nil {
		t.Fatalf("CloseMountsForTest(matching shared RO): %v", err)
	}

	for _, tc := range []struct {
		name   string
		mounts []Mount
	}{
		{
			name: "two-ro-different-caps",
			mounts: []Mount{
				{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro1", ReadOnly: true, SizeBytes: 32 << 20},
				{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro2", ReadOnly: true, SizeBytes: 64 << 20},
			},
		},
		{
			name: "capped-and-uncapped-ro",
			mounts: []Mount{
				{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro1", ReadOnly: true, SizeBytes: 32 << 20},
				{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro2", ReadOnly: true, SizeBytes: 0},
			},
		},
		{
			name: "overlay-lower-and-capped-ro",
			mounts: []Mount{
				{Kind: MountOverlay, VolumeName: "shared-ro", GuestPath: "/ovl"},
				{Kind: MountVolume, VolumeName: "shared-ro", GuestPath: "/ro1", ReadOnly: true, SizeBytes: 32 << 20},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{OCICacheDir: cacheDir, Mounts: tc.mounts}
			if err := cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("conflicting shared RO normalize() = %v, want ErrInvalidConfig", err)
			}
		})
	}

	// Grow an existing ext4lite image to 32 MiB and verify opening with a 16 MiB cap
	// fails with ErrInvalidConfig without truncating the image.
	requireCheckpointGuestBackend(t)
	_, layer := buildVolumeCapGuestLayer(t)
	oversizedImg := filepath.Join(t.TempDir(), "oversized.ext4")

	growCfg := newCheckpointTestConfig(t, cacheDir)
	growCfg.OCILayerTars = [][]byte{layer}
	growCfg.Mounts = []Mount{{Kind: MountVolume, ImagePath: oversizedImg, GuestPath: "/mnt"}}
	growCfg.Argv = []string{"/bin/volcap"}
	growCfg.Envv = []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"}
	growCfg.Stdin = strings.NewReader("fill /mnt/big.bin 14\nquit\n")
	var growOut bytes.Buffer
	growCfg.Stdout = &growOut
	growCfg.Stderr = io.Discard
	growSB, err := New(context.Background(), growCfg)
	if err != nil {
		t.Fatalf("New(grow): %v", err)
	}
	code, runErr := growSB.Run(context.Background())
	closeErr := growSB.Close()
	if runErr != nil || closeErr != nil || code != 0 || !strings.Contains(growOut.String(), "FILLED\n") {
		t.Fatalf("grow sandbox = (code=%d, runErr=%v, closeErr=%v, out=%q)", code, runErr, closeErr, growOut.String())
	}
	stBefore, err := os.Stat(oversizedImg)
	if err != nil || stBefore.Size() != 32<<20 {
		t.Fatalf("oversized.ext4 size before rejected open = (%v, %v), want 32 MiB", stBefore, err)
	}

	rejectCfg := newCheckpointTestConfig(t, cacheDir)
	rejectCfg.OCILayerTars = [][]byte{layer}
	rejectCfg.Mounts = []Mount{{Kind: MountVolume, ImagePath: oversizedImg, GuestPath: "/mnt", SizeBytes: 16 << 20}}
	rejectCfg.Argv = []string{"/bin/volcap"}
	if _, err := New(context.Background(), rejectCfg); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(16 MiB cap on 32 MiB image) = %v, want ErrInvalidConfig", err)
	}
	stAfter, err := os.Stat(oversizedImg)
	if err != nil || stAfter.Size() != 32<<20 {
		t.Fatalf("oversized.ext4 size after rejected open = (%v, %v), want 32 MiB preserved", stAfter, err)
	}
}

func TestEphemeralVolumeLifecycleIsolationAndOrphanCleanup(t *testing.T) {
	requireCheckpointGuestBackend(t)
	forceEphemeralStagingFallback.Store(true)
	t.Cleanup(func() { forceEphemeralStagingFallback.Store(false) })

	cacheDir := filepath.Join(t.TempDir(), "cache")
	if _, err := CreateVolume(cacheDir, "keepme", DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume(keepme): %v", err)
	}

	ephDir := filepath.Join(cacheDir, ephemeralVolumesDirName)
	if err := os.MkdirAll(ephDir, 0o700); err != nil {
		t.Fatal(err)
	}
	orphanStaging := filepath.Join(ephDir, "ephemeral-deadbeef.ext4.staging")
	unrelatedFile := filepath.Join(ephDir, "unrelated.note")
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(orphanStaging, []byte("orphan"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(unrelatedFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, layer := buildVolumeCapGuestLayer(t)
	var outBuf bytes.Buffer
	cfg := newCheckpointTestConfig(t, cacheDir)
	cfg.OCILayerTars = [][]byte{layer}
	cfg.Mounts = []Mount{
		{Kind: MountVolume, GuestPath: "/scratch", Ephemeral: true, SizeBytes: 32 << 20},
	}
	cfg.Argv = []string{"/bin/volcap"}
	cfg.Envv = []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"}
	cfg.Stdin = strings.NewReader("statfs /scratch\ncreate /scratch/note.txt ephemeral-ok\nfill /scratch/full.bin 40\nquit\n")
	cfg.Stdout = &outBuf
	cfg.Stderr = io.Discard

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(ephemeral): %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = sb.Close()
		}
	}()

	if UsesHostDirsForTest(sb) {
		t.Fatal("UsesHostDirsForTest = true for ephemeral ext4lite sandbox, want false")
	}
	if hm := HostMountsForTest(sb); len(hm) != 0 {
		t.Fatalf("HostMountsForTest = %+v, want empty", hm)
	}

	if runtime.GOOS != "windows" {
		if _, err := os.Stat(orphanStaging); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned staging file %q still exists: err = %v", orphanStaging, err)
		}
	} else {
		liveEntries, rErr := os.ReadDir(ephDir)
		if rErr != nil {
			t.Fatalf("ReadDir(%q) while open: %v", ephDir, rErr)
		}
		foundLiveExt4 := false
		for _, ent := range liveEntries {
			if strings.HasPrefix(ent.Name(), ephemeralStagingPrefix) && strings.HasSuffix(ent.Name(), ext4VolumeSuffix) {
				foundLiveExt4 = true
			}
		}
		if !foundLiveExt4 {
			t.Fatalf("expected live delete-on-close .ext4 file in %q while sandbox is open", ephDir)
		}
	}
	if got, err := os.ReadFile(unrelatedFile); err != nil || string(got) != "keep" {
		t.Fatalf("unrelated file = (%q, %v), want preserved", got, err)
	}

	vols, err := ListVolumes(cacheDir)
	if err != nil || len(vols) != 1 || vols[0].Name != "keepme" {
		t.Fatalf("ListVolumes = (%+v, %v), want only keepme", vols, err)
	}
	du, err := ComputeVolumeDiskUsage(cacheDir)
	if err != nil || du.Total != 1 || du.Active != 0 {
		t.Fatalf("ComputeVolumeDiskUsage = (%+v, %v), want Total=1 Active=0", du, err)
	}
	pruneRep, err := PruneVolumes(cacheDir)
	if err != nil || len(pruneRep.Deleted) != 1 || pruneRep.Deleted[0] != "keepme" {
		t.Fatalf("PruneVolumes = (%+v, %v), want only keepme deleted", pruneRep, err)
	}

	code, err := sb.Run(context.Background())
	if err != nil || code != 0 {
		t.Fatalf("ephemeral Run = (%d, %v), out=%q", code, err, outBuf.String())
	}
	closed = true
	if err := sb.Close(); err != nil {
		t.Fatalf("ephemeral Close: %v", err)
	}

	out := outBuf.String()
	if !strings.Contains(out, "CREATED\n") || !strings.Contains(out, "ENOSPC\n") {
		t.Fatalf("unexpected guest output: %q", out)
	}
	foundStatfs := false
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "STATFS:") {
			continue
		}
		foundStatfs = true
		parts := strings.Split(line, ":")
		blocks, bErr := strconv.ParseUint(parts[1], 10, 64)
		files, fErr := strconv.ParseUint(parts[2], 10, 64)
		if bErr != nil || fErr != nil || blocks == 0 || blocks > 8192 || files == 0 || files > 8192 {
			t.Fatalf("ephemeral 32 MiB STATFS line %q outside (0, 8192]", line)
		}
	}
	if !foundStatfs {
		t.Fatalf("missing STATFS output in %q", out)
	}

	entries, err := os.ReadDir(ephDir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", ephDir, err)
	}
	for _, ent := range entries {
		name := ent.Name()
		if name == "unrelated.note" || name == ephemeralLockFileName {
			continue
		}
		t.Fatalf("leftover file %q in ephemeral-volumes after Close", name)
	}
}

func TestEphemeralVolumeRejectsCheckpointWithoutMutatingStateOrOutput(t *testing.T) {
	requireCheckpointGuestBackend(t)
	_, layer := buildVolumeCapGuestLayer(t)
	cacheDir := t.TempDir()

	// 1. New rejects CheckpointDir combined with any ephemeral volume.
	badCfg := newCheckpointTestConfig(t, cacheDir)
	badCfg.OCILayerTars = [][]byte{layer}
	badCfg.CheckpointDir = t.TempDir()
	badCfg.Mounts = []Mount{{Kind: MountVolume, GuestPath: "/scratch", Ephemeral: true, SizeBytes: 16 << 20}}
	badCfg.Argv = []string{"/bin/volcap"}
	_, err := New(context.Background(), badCfg)
	if !errors.Is(err, ErrInvalidConfig) || !errors.Is(err, ErrCheckpointEphemeralVolume) {
		t.Fatalf("New(CheckpointDir + Ephemeral) = %v, want ErrInvalidConfig and ErrCheckpointEphemeralVolume", err)
	}

	// 2. Control listener remains valid; Checkpoint and CheckpointStream fail before
	// terminating active exec sessions, pausing the guest, or writing stream bytes,
	// and continue failing after remount ro and unmount.
	rs := startControlTestSandbox(t, Config{
		OCILayerTars: [][]byte{layer},
		OCICacheDir:  cacheDir,
		Mounts:       []Mount{{Kind: MountVolume, GuestPath: "/scratch", Ephemeral: true, SizeBytes: 16 << 20}},
		Argv:         []string{"/bin/volcap"},
		Envv:         []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
	})
	rs.stdout.waitForSubstring(t, "READY\n", 15*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	execStream, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
		Argv:  []string{"/bin/volcap"},
		Env:   []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
		Stdin: true,
	})
	if err != nil {
		t.Fatalf("OpenStream(exec.start): %v", err)
	}
	defer execStream.Close()
	if err := execStream.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("WaitResponse(exec.start): %v", err)
	}
	execOut := newNotifyBuffer()
	execDone := make(chan int, 1)
	go func() {
		_, _ = io.Copy(execOut, execStream.ChannelReader(ctx, control.ChannelStdout))
	}()
	go func() {
		ev, rErr := execStream.RecvEvent(ctx)
		if rErr != nil || ev.Type != "exec.exit" {
			execDone <- -1
			return
		}
		var exitEv control.ExecExitEvent
		if json.Unmarshal(ev.Data, &exitEv) != nil {
			execDone <- -1
			return
		}
		execDone <- exitEv.ExitCode
	}()
	execOut.waitForSubstring(t, "READY\n", 15*time.Second)

	if err := rs.sb.Checkpoint(ctx, CheckpointOptions{Force: true, LeaveRunning: false}); !errors.Is(err, ErrCheckpointEphemeralVolume) {
		t.Fatalf("Checkpoint(Force=true) = %v, want ErrCheckpointEphemeralVolume", err)
	}
	var tarBuf bytes.Buffer
	if err := rs.sb.CheckpointStream(ctx, CheckpointOptions{Force: true, LeaveRunning: false}, &tarBuf); !errors.Is(err, ErrCheckpointEphemeralVolume) {
		t.Fatalf("CheckpointStream(Force=true) = %v, want ErrCheckpointEphemeralVolume", err)
	}
	if tarBuf.Len() != 0 {
		t.Fatalf("CheckpointStream wrote %d bytes before failing, want 0", tarBuf.Len())
	}

	// Without CheckpointDir (which New forbids on ephemeral volumes), local
	// checkpoint RPC is disabled by policy while stream checkpoint RPC reaches
	// handleCheckpointStream and returns CodeUnsupported.
	if err := rs.client.Call(ctx, control.MethodCheckpoint, control.CheckpointRequest{Force: true, LeaveRunning: false}, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Fatalf("RPC MethodCheckpoint = %v, want CodeForbiddenByPolicy", err)
	}
	cs, err := rs.client.OpenStream(ctx, control.MethodCheckpointStream, control.CheckpointStreamRequest{Force: true, LeaveRunning: false})
	if err != nil {
		t.Fatalf("OpenStream(checkpoint_stream): %v", err)
	}
	if err := cs.WaitResponse(ctx, nil); !control.IsCode(err, control.CodeUnsupported) {
		cs.Close()
		t.Fatalf("RPC MethodCheckpointStream = %v, want CodeUnsupported", err)
	}
	cs.Close()

	// Verify the active exec session was NOT killed by Force=true.
	execStdin := execStream.ChannelWriter(ctx, control.ChannelStdin, false)
	if _, err := io.WriteString(execStdin, "create /scratch/exec.txt alive\nquit\n"); err != nil {
		t.Fatalf("write to exec stdin: %v", err)
	}
	_ = execStdin.Close()
	execOut.waitForSubstring(t, "CREATED\n", 10*time.Second)
	if code := <-execDone; code != 0 {
		t.Fatalf("exec session exit code = %d, want 0 (unharmed by rejected Force checkpoint)", code)
	}

	// Remount ro and unmount /scratch; checkpoint remains forbidden for the sandbox lifetime.
	if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
		Target: "/scratch", ReadOnly: true,
	}, nil); err != nil {
		t.Fatalf("mount.remount /scratch ro: %v", err)
	}
	if err := rs.sb.CheckpointStream(ctx, CheckpointOptions{LeaveRunning: true}, &tarBuf); !errors.Is(err, ErrCheckpointEphemeralVolume) {
		t.Fatalf("CheckpointStream after remount ro = %v, want ErrCheckpointEphemeralVolume", err)
	}
	if err := rs.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{
		Target: "/scratch",
	}, nil); err != nil {
		t.Fatalf("mount.remove /scratch: %v", err)
	}
	if err := rs.sb.CheckpointStream(ctx, CheckpointOptions{LeaveRunning: true}, &tarBuf); !errors.Is(err, ErrCheckpointEphemeralVolume) {
		t.Fatalf("CheckpointStream after mount.remove = %v, want ErrCheckpointEphemeralVolume", err)
	}
}

func TestCheckpointAndRestoreCappedVolumesManifestV3AndPreflight(t *testing.T) {
	requireCheckpointGuestBackend(t)
	_, layer := buildVolumeCapGuestLayer(t)
	cacheDir := t.TempDir()

	// 1. Verify NAT-policy uncapped checkpoints keep manifest version 2 without nat_policy_required.
	const natPolicyJSON = `{"egress":{"default":"deny"},"ingress":{"default":"deny"}}`
	natPol, err := ParseNATPolicy(strings.NewReader(natPolicyJSON))
	if err != nil {
		t.Fatalf("ParseNATPolicy: %v", err)
	}
	ckptV2 := t.TempDir()
	rsV2 := startControlTestSandbox(t, Config{
		OCILayerTars:  [][]byte{layer},
		OCICacheDir:   cacheDir,
		CheckpointDir: ckptV2,
		NetworkMode:   NetModeNAT,
		NetworkPolicy: &natPol,
		Argv:          []string{"/bin/volcap"},
		Envv:          []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
	})
	rsV2.stdout.waitForSubstring(t, "READY\n", 15*time.Second)
	if err := rsV2.sb.Checkpoint(context.Background(), CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint v2: %v", err)
	}
	<-rsV2.runDone
	_ = rsV2.sb.Close()
	rawV2, err := os.ReadFile(filepath.Join(ckptV2, checkpointManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawV2), `"nat_policy_required"`) || strings.Contains(string(rawV2), `"volume_limit"`) {
		t.Fatalf("v2 manifest unexpectedly contains v3 keys:\n%s", rawV2)
	}
	manV2, err := readAndParseManifest(ckptV2)
	if err != nil || manV2.Version != checkpointManifestNATPolicyVersion {
		t.Fatalf("v2 manifest = (%+v, %v), want version %d", manV2, err, checkpointManifestNATPolicyVersion)
	}
	// Restore rejects adding a size limit to an uncapped mount in a v1/v2 bundle.
	uncappedVol := filepath.Join(t.TempDir(), "uncapped.ext4")
	if _, err := Restore(context.Background(), Config{
		OCICacheDir:   cacheDir,
		OCILayerTars:  [][]byte{layer},
		NetworkMode:   NetModeNAT,
		NetworkPolicy: &natPol,
		Mounts:        []Mount{{Kind: MountVolume, ImagePath: uncappedVol, GuestPath: "/mnt/cap", SizeBytes: 16 << 20}},
	}, RestoreOptions{Dir: ckptV2}); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("Restore(uncapped v2 with new SizeBytes) = %v, want ErrCheckpointManifest", err)
	}

	// 2. Verify lazy-detach guard on an isolated sandbox: while a detached capped
	// volume still has an open guest descriptor, both Checkpoint and CheckpointStream
	// fail before truncating existing checkpoint files.
	volDetach := filepath.Join(t.TempDir(), "detach.ext4")
	ckptDetach := t.TempDir()
	rsDet := startControlTestSandbox(t, Config{
		OCILayerTars:  [][]byte{layer},
		OCICacheDir:   cacheDir,
		CheckpointDir: ckptDetach,
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volDetach, GuestPath: "/mnt/cap", SizeBytes: 32 << 20},
		},
		Argv: []string{"/bin/volcap"},
		Envv: []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
	})
	rsDet.stdout.waitForSubstring(t, "READY\n", 15*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	if _, err := io.WriteString(rsDet.stdinW, "create /mnt/cap/data.txt detach-test\nopen /mnt/cap/data.txt\n"); err != nil {
		t.Fatal(err)
	}
	rsDet.stdout.waitForSubstring(t, "OPENED:detach-test\n", 15*time.Second)
	if err := rsDet.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: true}); err != nil {
		t.Fatalf("baseline Checkpoint before detach: %v", err)
	}
	stateInfoBefore, err := os.Stat(filepath.Join(ckptDetach, checkpointStateFileName))
	if err != nil || stateInfoBefore.Size() == 0 {
		t.Fatalf("state.img before detached checkpoint = (%v, %v)", stateInfoBefore, err)
	}
	if err := rsDet.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{
		Target: "/mnt/cap", Detach: true,
	}, nil); err != nil {
		t.Fatalf("mount.remove --detach /mnt/cap: %v", err)
	}
	if err := rsDet.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: true}); err == nil {
		t.Fatal("Checkpoint succeeded while detached capped volume still had open guest descriptor")
	}
	var detachedTar bytes.Buffer
	if err := rsDet.sb.CheckpointStream(ctx, CheckpointOptions{LeaveRunning: true}, &detachedTar); err == nil {
		t.Fatal("CheckpointStream succeeded while detached capped volume still had open guest descriptor")
	}
	stateInfoAfter, err := os.Stat(filepath.Join(ckptDetach, checkpointStateFileName))
	if err != nil || stateInfoAfter.Size() != stateInfoBefore.Size() {
		t.Fatalf("failed detached Checkpoint mutated state.img size: got %v, want %d", stateInfoAfter, stateInfoBefore.Size())
	}
	_, _ = io.WriteString(rsDet.stdinW, "quit\n")
	<-rsDet.runDone
	_ = rsDet.sb.Close()

	// 2b. Save a clean stop checkpoint (Manifest v3) of a capped persistent volume for Restore.
	volCap := filepath.Join(t.TempDir(), "capped.ext4")
	ckptV3 := t.TempDir()
	rs := startControlTestSandbox(t, Config{
		OCILayerTars:  [][]byte{layer},
		OCICacheDir:   cacheDir,
		CheckpointDir: ckptV3,
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/cap", SizeBytes: 32 << 20},
		},
		Argv: []string{"/bin/volcap"},
		Envv: []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
	})
	rs.stdout.waitForSubstring(t, "READY\n", 15*time.Second)

	if _, err := io.WriteString(rs.stdinW, "create /mnt/cap/data.txt hello-v3\nopen /mnt/cap/data.txt\n"); err != nil {
		t.Fatal(err)
	}
	rs.stdout.waitForSubstring(t, "OPENED:hello-v3\n", 15*time.Second)

	if err := rs.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint v3 (LeaveRunning=false): %v", err)
	}
	<-rs.runDone
	_ = rs.sb.Close()

	rawV3, err := os.ReadFile(filepath.Join(ckptV3, checkpointManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawV3), `"nat_policy_required": false`) {
		t.Fatalf("v3 manifest missing explicit nat_policy_required=false:\n%s", rawV3)
	}
	manV3, err := readAndParseManifest(ckptV3)
	if err != nil {
		t.Fatalf("readAndParseManifest(v3): %v", err)
	}
	if manV3.Version != checkpointManifestVolumeLimitVersion {
		t.Fatalf("manV3.Version = %d, want %d", manV3.Version, checkpointManifestVolumeLimitVersion)
	}
	if len(manV3.Mounts) != 1 || manV3.Mounts[0].VolumeLimit == nil || manV3.Mounts[0].VolumeLimit.MaxBytes != 32<<20 {
		t.Fatalf("manV3.Mounts = %+v, want MaxBytes=32 MiB", manV3.Mounts)
	}

	// 3. Preflight negative matrix on mutated copies of ckptV3.
	baseRestoreCfg := func(imgPath string, sizeBytes int64, ro bool) Config {
		cfg := newCheckpointTestConfig(t, cacheDir)
		cfg.OCILayerTars = [][]byte{layer}
		cfg.Mounts = []Mount{{
			Kind:      MountVolume,
			ImagePath: imgPath,
			GuestPath: "/mnt/cap",
			SizeBytes: sizeBytes,
			ReadOnly:  ro,
		}}
		return cfg
	}

	// Mismatched explicit SizeBytes.
	if _, err := Restore(ctx, baseRestoreCfg(volCap, 64<<20, false), RestoreOptions{Dir: ckptV3}); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("Restore(mismatched SizeBytes) = %v, want ErrCheckpointManifest", err)
	}
	// Writable guest view in manifest cannot restore with ReadOnly backing config.
	if _, err := Restore(ctx, baseRestoreCfg(volCap, 32<<20, true), RestoreOptions{Dir: ckptV3}); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("Restore(writable manifest + RO config) = %v, want ErrCheckpointManifest", err)
	}
	// Ephemeral mount in Restore config rejected with ErrInvalidConfig.
	ephRestoreCfg := newCheckpointTestConfig(t, cacheDir)
	ephRestoreCfg.OCILayerTars = [][]byte{layer}
	ephRestoreCfg.Mounts = []Mount{{Kind: MountVolume, GuestPath: "/mnt/cap", Ephemeral: true, SizeBytes: 32 << 20}}
	if _, err := Restore(ctx, ephRestoreCfg, RestoreOptions{Dir: ckptV3}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Restore(Ephemeral config) = %v, want ErrInvalidConfig", err)
	}
	// Missing persistent image fails without creating the file.
	missingImg := filepath.Join(t.TempDir(), "missing.ext4")
	if _, err := Restore(ctx, baseRestoreCfg(missingImg, 0, false), RestoreOptions{Dir: ckptV3}); err == nil {
		t.Fatal("Restore(missing image) succeeded, want error")
	}
	if _, statErr := os.Stat(missingImg); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Restore created missing persistent image %q: statErr=%v", missingImg, statErr)
	}

	writeMutatedManifest := func(mutate func(*CheckpointManifest)) string {
		dir := copyCheckpointBundleDir(t, ckptV3)
		m := manV3
		m.Mounts = append([]ManifestMount(nil), manV3.Mounts...)
		mutate(&m)
		b, mErr := json.Marshal(m)
		if mErr != nil {
			t.Fatal(mErr)
		}
		if wErr := os.WriteFile(filepath.Join(dir, checkpointManifestFileName), b, 0o600); wErr != nil {
			t.Fatal(wErr)
		}
		return dir
	}

	trueVal := true
	for _, tc := range []struct {
		name   string
		mutate func(*CheckpointManifest)
		cfg    Config
	}{
		{
			name: "v3-without-capped-mounts",
			mutate: func(m *CheckpointManifest) {
				m.Mounts[0].VolumeLimit = nil
			},
			cfg: baseRestoreCfg(volCap, 0, false),
		},
		{
			name: "v1-with-volume-limit",
			mutate: func(m *CheckpointManifest) {
				m.Version = CheckpointManifestVersion
			},
			cfg: baseRestoreCfg(volCap, 32<<20, false),
		},
		{
			name: "v3-unaligned-max-bytes",
			mutate: func(m *CheckpointManifest) {
				m.Mounts[0].VolumeLimit = &ManifestVolumeLimit{MaxBytes: 20 << 20}
			},
			cfg: baseRestoreCfg(volCap, 0, false),
		},
		{
			name: "v3-zero-max-bytes",
			mutate: func(m *CheckpointManifest) {
				m.Mounts[0].VolumeLimit = &ManifestVolumeLimit{MaxBytes: 0}
			},
			cfg: baseRestoreCfg(volCap, 0, false),
		},
		{
			name: "duplicate-guest-paths",
			mutate: func(m *CheckpointManifest) {
				m.Mounts = append(m.Mounts, m.Mounts[0])
			},
			cfg: baseRestoreCfg(volCap, 32<<20, false),
		},
		{
			name: "manifest-ephemeral-true",
			mutate: func(m *CheckpointManifest) {
				m.Mounts[0].Ephemeral = true
			},
			cfg: baseRestoreCfg(volCap, 32<<20, false),
		},
		{
			name: "writable-guest-with-ro-backing",
			mutate: func(m *CheckpointManifest) {
				m.Mounts[0].ReadOnly = false
				m.Mounts[0].BackingReadOnly = &trueVal
			},
			cfg: baseRestoreCfg(volCap, 32<<20, false),
		},
		{
			name: "v3-nat-policy-required-non-nat",
			mutate: func(m *CheckpointManifest) {
				m.NATPolicyRequired = true
				m.NetMode = NetModeNone
			},
			cfg: func() Config {
				c := baseRestoreCfg(volCap, 32<<20, false)
				c.NetworkPolicy = &natPol
				return c
			}(),
		},
		{
			name: "v3-nat-policy-required-missing-policy",
			mutate: func(m *CheckpointManifest) {
				m.NATPolicyRequired = true
				m.NetMode = NetModeNAT
			},
			cfg: func() Config {
				c := baseRestoreCfg(volCap, 32<<20, false)
				c.NetworkMode = NetModeNAT
				return c
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			badDir := writeMutatedManifest(tc.mutate)
			if _, err := Restore(ctx, tc.cfg, RestoreOptions{Dir: badDir}); !errors.Is(err, ErrCheckpointManifest) {
				t.Fatalf("Restore(%s) = %v, want ErrCheckpointManifest", tc.name, err)
			}
		})
	}

	// 4. Restore ckptV3 with omitted SizeBytes (inherits 32 MiB), verify open FD and
	// capacity enforcement, close FD, remount ro, and save chained v3 checkpoint.
	ckptChain := t.TempDir()
	rs1, close1 := startRestoredControlSandbox(t, Config{
		OCICacheDir:   cacheDir,
		OCILayerTars:  [][]byte{layer},
		CheckpointDir: ckptChain,
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/cap"},
		},
	}, ckptV3)
	blurred1 := false
	defer func() {
		if !blurred1 {
			close1()
		}
	}()

	var ml1 control.MountListResponse
	if err := rs1.client.Call(ctx, control.MethodMountList, nil, &ml1); err != nil {
		t.Fatalf("mount.list on restored sandbox: %v", err)
	}
	if _, err := io.WriteString(rs1.stdinW, "read\nfill /mnt/cap/overflow.bin 40\nunlink /mnt/cap/overflow.bin\nclose\n"); err != nil {
		t.Fatal(err)
	}
	rs1.stdout.waitForSubstring(t, "READ:hello-v3\n", 20*time.Second)
	rs1.stdout.waitForSubstring(t, "ENOSPC\n", 20*time.Second)
	rs1.stdout.waitForSubstring(t, "CLOSED\n", 20*time.Second)

	capStat, err := os.Stat(volCap)
	if err != nil || capStat.Size() > 32<<20 {
		t.Fatalf("volCap size after ENOSPC on restored sandbox = (%v, %v), want <= 32 MiB", capStat, err)
	}

	if err := rs1.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
		Target: "/mnt/cap", ReadOnly: true,
	}, nil); err != nil {
		t.Fatalf("mount.remount /mnt/cap ro before chained checkpoint: %v", err)
	}
	if err := rs1.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("chained Checkpoint(LeaveRunning=false): %v", err)
	}
	blurred1 = true
	close1()

	manChain, err := readAndParseManifest(ckptChain)
	if err != nil {
		t.Fatalf("readAndParseManifest(ckptChain): %v", err)
	}
	if manChain.Version != checkpointManifestVolumeLimitVersion || len(manChain.Mounts) != 1 ||
		manChain.Mounts[0].VolumeLimit == nil || manChain.Mounts[0].VolumeLimit.MaxBytes != 32<<20 ||
		!manChain.Mounts[0].ReadOnly || manChain.Mounts[0].BackingReadOnly == nil || *manChain.Mounts[0].BackingReadOnly {
		t.Fatalf("chained manifest = %+v, want v3 with MaxBytes=32 MiB, ReadOnly=true, BackingReadOnly=false", manChain)
	}

	// 5. Restore chained remounted-ro checkpoint: ReadOnly=true on config must fail
	// because the saved backing was writable; ReadOnly=false with matching SizeBytes
	// succeeds, starts ro in guest, and allows remounting back to rw.
	if _, err := Restore(ctx, baseRestoreCfg(volCap, 32<<20, true), RestoreOptions{Dir: ckptChain}); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("Restore(remounted-ro writable backing with ReadOnly=true) = %v, want ErrCheckpointManifest", err)
	}

	rs2, close2 := startRestoredControlSandbox(t, Config{
		OCICacheDir:  cacheDir,
		OCILayerTars: [][]byte{layer},
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/cap", SizeBytes: 32 << 20},
		},
	}, ckptChain)
	blurred2 := false
	defer func() {
		if !blurred2 {
			close2()
		}
	}()

	var ml2 control.MountListResponse
	if err := rs2.client.Call(ctx, control.MethodMountList, nil, &ml2); err != nil {
		t.Fatalf("mount.list on second restore: %v", err)
	}
	foundRO := false
	for _, m := range ml2.Mounts {
		if m.Target == "/mnt/cap" {
			foundRO = m.ReadOnly
		}
	}
	if !foundRO {
		t.Fatalf("expected /mnt/cap ReadOnly=true after restore, got %+v", ml2.Mounts)
	}
	if err := rs2.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
		Target: "/mnt/cap", ReadOnly: false,
	}, nil); err != nil {
		t.Fatalf("mount.remount /mnt/cap rw after restore: %v", err)
	}
	blurred2 = true
	close2()

	// 6. Shared read-only capped mounts: Restore inherits omitted SizeBytes on one
	// mount while the sibling specifies SizeBytes explicitly, and cleanly removing
	// the secondary mount still checkpoints cleanly.
	ckptSharedRO := t.TempDir()
	rsShared := startControlTestSandbox(t, Config{
		OCILayerTars:  [][]byte{layer},
		OCICacheDir:   cacheDir,
		CheckpointDir: ckptSharedRO,
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/ro1", ReadOnly: true, SizeBytes: 32 << 20},
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/ro2", ReadOnly: true, SizeBytes: 32 << 20},
		},
		Argv: []string{"/bin/volcap"},
		Envv: []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
	})
	rsShared.stdout.waitForSubstring(t, "READY\n", 15*time.Second)
	if err := rsShared.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint(shared RO): %v", err)
	}
	<-rsShared.runDone
	_ = rsShared.sb.Close()

	ckptAfterRemove := t.TempDir()
	rsSharedRestored, closeSharedRestored := startRestoredControlSandbox(t, Config{
		OCICacheDir:   cacheDir,
		OCILayerTars:  [][]byte{layer},
		CheckpointDir: ckptAfterRemove,
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/ro1", ReadOnly: true, SizeBytes: 32 << 20},
			{Kind: MountVolume, ImagePath: volCap, GuestPath: "/mnt/ro2", ReadOnly: true},
		},
	}, ckptSharedRO)
	blurredShared := false
	defer func() {
		if !blurredShared {
			closeSharedRestored()
		}
	}()
	if err := rsSharedRestored.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{
		Target: "/mnt/ro2",
	}, nil); err != nil {
		t.Fatalf("mount.remove /mnt/ro2: %v", err)
	}
	if err := rsSharedRestored.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint after removing secondary shared RO mount: %v", err)
	}
	blurredShared = true
	closeSharedRestored()
	manAfterRemove, err := readAndParseManifest(ckptAfterRemove)
	if err != nil || manAfterRemove.Version != checkpointManifestVolumeLimitVersion || len(manAfterRemove.Mounts) != 1 || manAfterRemove.Mounts[0].GuestPath != "/mnt/ro1" {
		t.Fatalf("manifest after secondary RO mount removal = (%+v, %v), want v3 with /mnt/ro1 only", manAfterRemove, err)
	}

	// 7. In-guest clean umount(2) of a capped volume prunes the stale mount entry
	// instead of writing a phantom v3 volume_limit entry.
	volUmount := filepath.Join(t.TempDir(), "umount.ext4")
	ckptUmount := t.TempDir()
	rsUmount := startControlTestSandbox(t, Config{
		OCILayerTars:  [][]byte{layer},
		OCICacheDir:   cacheDir,
		CheckpointDir: ckptUmount,
		Mounts: []Mount{
			{Kind: MountVolume, ImagePath: volUmount, GuestPath: "/mnt/cap", SizeBytes: 16 << 20},
		},
		Argv: []string{"/bin/volcap"},
		Envv: []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
	})
	rsUmount.stdout.waitForSubstring(t, "READY\n", 15*time.Second)
	if _, err := io.WriteString(rsUmount.stdinW, "umount /mnt/cap\n"); err != nil {
		t.Fatal(err)
	}
	rsUmount.stdout.waitForSubstring(t, "UMOUNTED\n", 15*time.Second)
	if err := rsUmount.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint after in-guest umount: %v", err)
	}
	<-rsUmount.runDone
	_ = rsUmount.sb.Close()
	manUmount, err := readAndParseManifest(ckptUmount)
	if err != nil || manUmount.Version != CheckpointManifestVersion || len(manUmount.Mounts) != 0 {
		t.Fatalf("manifest after in-guest umount = (%+v, %v), want v1 with 0 mounts", manUmount, err)
	}
}
