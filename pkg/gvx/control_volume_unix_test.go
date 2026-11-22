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

//go:build linux || darwin

package gvx

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
)

func execRunOutputAndCode(t *testing.T, ctx context.Context, client *control.Client, req control.ExecStartRequest) (string, int) {
	t.Helper()
	st, err := client.OpenStream(ctx, control.MethodExecStart, req)
	if err != nil {
		t.Fatalf("exec %v open: %v", req.Argv, err)
	}
	defer st.Close()
	if err := st.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("exec %v wait: %v", req.Argv, err)
	}
	out, readErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
	ev, evErr := st.RecvEvent(ctx)
	if readErr != nil || evErr != nil || ev.Type != "exec.exit" {
		t.Fatalf("exec %v stream: out=%q readErr=%v ev=%+v evErr=%v", req.Argv, out, readErr, ev, evErr)
	}
	var exitEv control.ExecExitEvent
	if err := json.Unmarshal(ev.Data, &exitEv); err != nil {
		t.Fatalf("exec %v decode exit: %v", req.Argv, err)
	}
	return string(out), exitEv.ExitCode
}

func TestControlVolumeAttachRemountAndLockRelease(t *testing.T) {
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	helloELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "vol-exec-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64: %v", err)
	}
	write1ELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/vol/guest.txt", "written-to-ext4\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(1): %v", err)
	}
	write2ELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/vol/after_rw.txt", "rw-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(2): %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/write1", Data: write1ELF, Mode: 0o755},
		testimage.File{Name: "bin/write2", Data: write2ELF, Mode: 0o755},
		testimage.File{Name: "etc/seed.txt", Data: []byte("vol-ready\n"), Mode: 0o644},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "volctrl", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/seed.txt", "/proc/self/fd/0"},
	})

	rs := startControlTestSandbox(t, Config{
		Name:              "vol-attach",
		OCIImage:          "volctrl:latest",
		RegistryBaseURL:   regURL,
		AllowVolumeAttach: true,
	})
	rs.stdout.waitForSubstring(t, "vol-ready\n", 15*time.Second)
	ctx := context.Background()

	// 1. Non-regular FDs (directory and pipe) must be rejected with INVALID_ARGUMENT.
	dirF, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{
		Type:   "volume",
		Target: "/mnt/bad-dir",
		Source: "dir",
	}, nil, int(dirF.Fd()))
	_ = dirF.Close()
	if !control.IsCode(err, control.CodeInvalidArgument) {
		t.Fatalf("volume attach directory FD err = %v, want INVALID_ARGUMENT", err)
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	err = rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{
		Type:   "volume",
		Target: "/mnt/bad-pipe",
		Source: "pipe",
	}, nil, int(pipeR.Fd()))
	_ = pipeR.Close()
	_ = pipeW.Close()
	if !control.IsCode(err, control.CodeInvalidArgument) {
		t.Fatalf("volume attach pipe FD err = %v, want INVALID_ARGUMENT", err)
	}

	// 2. Format a fresh ext4lite volume image and attach it RW via SCM_RIGHTS.
	volPath := filepath.Join(t.TempDir(), "dyn.ext4")
	initF, err := os.OpenFile(volPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create volume image: %v", err)
	}
	initVol, err := ext4lite.OpenVolume(initF, ext4lite.VolumeOptions{})
	if err != nil {
		t.Fatalf("format ext4lite volume: %v", err)
	}
	if err := initVol.Close(); err != nil {
		t.Fatalf("close formatted volume: %v", err)
	}

	rwF, err := os.OpenFile(volPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open volume image RW: %v", err)
	}
	var mountInfo control.MountInfo
	err = rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{
		Type:   "volume",
		Target: "/mnt/vol",
		Source: "dyn.ext4",
	}, &mountInfo, int(rwF.Fd()))
	// Close the client descriptor immediately so only the sandbox owns the open file.
	_ = rwF.Close()
	if err != nil {
		t.Fatalf("mount.add volume RW: %v", err)
	}
	if mountInfo.Type != "ext4lite" || mountInfo.ReadOnly || !mountInfo.Mutable {
		t.Fatalf("mountInfo = %+v, want ext4lite rw mutable", mountInfo)
	}

	// Sandbox must hold an exclusive OS lock while the volume is mounted RW.
	if mode, err := ext4lite.ProbeVolumeLock(volPath); err != nil || mode != ext4lite.VolumeLockExclusive {
		t.Fatalf("ProbeVolumeLock while RW mounted = (%v, %v), want (exclusive, nil)", mode, err)
	}

	// Guest writes and reads back a file on the attached ext4lite volume.
	if _, code := execRunOutputAndCode(t, ctx, rs.client, control.ExecStartRequest{Argv: []string{"/bin/write1"}}); code != 0 {
		t.Fatalf("guest write to attached ext4lite volume exited %d, want 0", code)
	}
	if out, code := execRunOutputAndCode(t, ctx, rs.client, control.ExecStartRequest{Argv: []string{"/bin/cat", "/mnt/vol/guest.txt"}}); code != 0 || out != "written-to-ext4\n" {
		t.Fatalf("guest read from attached volume = (%q, %d), want written-to-ext4", out, code)
	}

	// Import an executable ELF onto the attached volume and execute it to
	// verify SetChunkMemory / mapped execution on dynamically attached ext4lite.
	{
		var binTar bytes.Buffer
		tw := tar.NewWriter(&binTar)
		if err := tw.WriteHeader(&tar.Header{Name: "runme", Mode: 0o755, Size: int64(len(helloELF))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(helloELF); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		impSt, err := rs.client.OpenStream(ctx, control.MethodFSImport, control.FSImportRequest{DestPath: "/mnt/vol"})
		if err != nil {
			t.Fatalf("fs.import into /mnt/vol open: %v", err)
		}
		w := impSt.ChannelWriter(ctx, control.ChannelGeneric, false)
		_, _ = w.Write(binTar.Bytes())
		_ = w.Close()
		if err := impSt.WaitResponse(ctx, nil); err != nil {
			impSt.Close()
			t.Fatalf("fs.import into /mnt/vol resp: %v", err)
		}
		impSt.Close()

		if out, code := execRunOutputAndCode(t, ctx, rs.client, control.ExecStartRequest{Argv: []string{"/mnt/vol/runme"}}); code != 0 || out != "vol-exec-ok\n" {
			t.Fatalf("exec /mnt/vol/runme = (%q, %d), want (vol-exec-ok, 0)", out, code)
		}
	}

	// Remount RO blocks guest writes; remount back to RW allows guest writes again.
	if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
		Target:   "/mnt/vol",
		ReadOnly: true,
	}, nil); err != nil {
		t.Fatalf("mount.remount /mnt/vol ro: %v", err)
	}
	if _, code := execRunOutputAndCode(t, ctx, rs.client, control.ExecStartRequest{Argv: []string{"/bin/write2"}}); code == 0 {
		t.Fatal("guest write succeeded on ro-remounted ext4lite volume, want non-zero exit")
	}
	if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
		Target:   "/mnt/vol",
		ReadOnly: false,
	}, nil); err != nil {
		t.Fatalf("mount.remount /mnt/vol rw: %v", err)
	}
	if _, code := execRunOutputAndCode(t, ctx, rs.client, control.ExecStartRequest{Argv: []string{"/bin/write2"}}); code != 0 {
		t.Fatalf("guest write after rw remount exited %d, want 0", code)
	}

	// 3. Unmount while sandbox stays running: exclusive flock must be released immediately.
	if err := rs.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{
		Target: "/mnt/vol",
		Detach: false,
	}, nil); err != nil {
		t.Fatalf("mount.remove /mnt/vol: %v", err)
	}
	if mode, err := ext4lite.ProbeVolumeLock(volPath); err != nil || mode != ext4lite.VolumeLockNone {
		t.Fatalf("ProbeVolumeLock after mount.remove = (%v, %v), want (none, nil)", mode, err)
	}
	reopenF, err := os.OpenFile(volPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen volume after unmount: %v", err)
	}
	reopenVol, err := ext4lite.OpenVolume(reopenF, ext4lite.VolumeOptions{ReadOnly: false})
	if err != nil {
		t.Fatalf("OpenVolume(RW) while sandbox still running: %v", err)
	}
	if err := reopenVol.Close(); err != nil {
		t.Fatalf("close reopened volume: %v", err)
	}

	// 4. Re-attach the same volume ReadOnly: verifies persistence, LOCK_SH, and RO->RW refusal.
	roF, err := os.Open(volPath)
	if err != nil {
		t.Fatalf("open volume RO: %v", err)
	}
	var roInfo control.MountInfo
	err = rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{
		Type:     "volume",
		Target:   "/mnt/volro",
		Source:   "dyn.ext4",
		ReadOnly: true,
	}, &roInfo, int(roF.Fd()))
	_ = roF.Close()
	if err != nil {
		t.Fatalf("mount.add volume RO: %v", err)
	}
	if !roInfo.ReadOnly || roInfo.Mutable {
		t.Fatalf("roInfo = %+v, want ReadOnly=true Mutable=false", roInfo)
	}
	if mode, err := ext4lite.ProbeVolumeLock(volPath); err != nil || mode != ext4lite.VolumeLockShared {
		t.Fatalf("ProbeVolumeLock while RO mounted = (%v, %v), want (shared, nil)", mode, err)
	}
	if out, code := execRunOutputAndCode(t, ctx, rs.client, control.ExecStartRequest{Argv: []string{"/bin/cat", "/mnt/volro/guest.txt"}}); code != 0 || out != "written-to-ext4\n" {
		t.Fatalf("persisted file after RO re-attach = (%q, %d), want written-to-ext4", out, code)
	}
	if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
		Target:   "/mnt/volro",
		ReadOnly: false,
	}, nil); !control.IsCode(err, control.CodeLockdownDenied) {
		t.Fatalf("remount RO volume to RW err = %v, want LOCKDOWN_DENIED", err)
	}
	if err := rs.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{
		Target: "/mnt/volro",
	}, nil); err != nil {
		t.Fatalf("mount.remove /mnt/volro: %v", err)
	}
	if mode, err := ext4lite.ProbeVolumeLock(volPath); err != nil || mode != ext4lite.VolumeLockNone {
		t.Fatalf("ProbeVolumeLock after RO unmount = (%v, %v), want (none, nil)", mode, err)
	}
}
