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

package gvx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testimage"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/gvx/shm"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type hvfShmTestExt struct {
	file   *os.File
	region *shm.ImportedRegion
}

func (*hvfShmTestExt) Name() string                 { return "hvf-shm-test" }
func (*hvfShmTestExt) Validate(ValidationEnv) error { return nil }

func (e *hvfShmTestExt) OpenPreLockdown(_ context.Context, env PreLockdownEnv) (BoundExtension, error) {
	reg, err := env.SharedMemory.ImportFD(int(e.file.Fd()), 0, env.HostMappingAlign, true)
	if err != nil {
		return nil, err
	}
	e.region = reg
	return &hvfShmTestBound{region: reg}, nil
}

type hvfShmTestBound struct {
	region *shm.ImportedRegion
}

func (*hvfShmTestBound) NeedsHelperSpawn() bool                  { return false }
func (*hvfShmTestBound) LockdownRequirements() ExtensionLockdown { return ExtensionLockdown{} }
func (*hvfShmTestBound) CheckpointPolicy() CheckpointPolicy      { return CheckpointUnsupported }
func (*hvfShmTestBound) SysfsTopologies() []sys.TopologyAddition { return nil }
func (*hvfShmTestBound) AbortPending()                           {}
func (b *hvfShmTestBound) Close(guestUnmapped bool) error {
	if guestUnmapped && b.region != nil {
		b.region.Release()
	}
	return nil
}
func (*hvfShmTestBound) Inspect() (json.RawMessage, error) { return nil, nil }
func (*hvfShmTestBound) Stats() (json.RawMessage, error)   { return nil, nil }

func (b *hvfShmTestBound) AttachKernel(_ context.Context, kenv *KernelEnv) error {
	return kenv.VFS.RegisterDevice(vfs.CharDevice, 226, 129, &hvfShmDevice{region: b.region}, &vfs.RegisterDeviceOptions{
		GroupName: "hvfshm",
		Pathname:  "hvfshm0",
		FilePerms: 0o666,
	})
}

type hvfShmDevice struct {
	region *shm.ImportedRegion
}

func (d *hvfShmDevice) Open(ctx gvcontext.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &hvfShmFD{region: d.region}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

type hvfShmFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	region *shm.ImportedRegion
}

func (*hvfShmFD) Release(gvcontext.Context) {}

func (fd *hvfShmFD) ConfigureMMap(_ gvcontext.Context, opts *memmap.MMapOpts) error {
	if err := fd.region.ConfigureMMap(opts); err != nil {
		return err
	}
	return vfs.GenericConfigureMMap(&fd.vfsfd, fd.region, opts)
}

func buildHVFShmProbeELF(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling hvf shm guest probe")
	}
	srcDir := t.TempDir()
	src := `package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	fd, err := syscall.Open("/dev/hvfshm0", syscall.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open /dev/hvfshm0: %v\n", err)
		os.Exit(2)
	}
	defer syscall.Close(fd)

	// PROT_EXEC must be refused on imported shared memory.
	if _, err := syscall.Mmap(fd, 0, 16384, syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_SHARED); err == nil {
		fmt.Fprintln(os.Stderr, "expected PROT_EXEC mmap to fail")
		os.Exit(3)
	}

	buf, err := syscall.Mmap(fd, 0, 16384, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mmap rw: %v\n", err)
		os.Exit(4)
	}
	defer syscall.Munmap(buf)

	if string(buf[:11]) != "HOST_SEED42" {
		fmt.Fprintf(os.Stderr, "host seed = %q, want HOST_SEED42\n", string(buf[:11]))
		os.Exit(5)
	}
	copy(buf[64:], "GUEST_ZERO_COPY_OK")
	fmt.Println("SHM_OK")
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module shmprobe\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "shmprobe")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest shmprobe: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read shmprobe: %v", err)
	}
	return data
}

func TestHVFZeroCopySharedMemoryGuestReadWriteAndNoExec(t *testing.T) {
	requireCheckpointGuestBackend(t)

	backing, err := os.CreateTemp(t.TempDir(), "hvf-shm-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer backing.Close()
	if err := backing.Truncate(16384); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if _, err := backing.WriteAt([]byte("HOST_SEED42"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	probeELF := buildHVFShmProbeELF(t)
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/shmprobe", Data: probeELF, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	ext := &hvfShmTestExt{file: backing}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sb, err := New(ctx, Config{
		Platform:            PlatformHVF,
		NetworkMode:         NetModeNone,
		OCILayerTars:        [][]byte{layer},
		OCICacheDir:         t.TempDir(),
		Argv:                []string{"/bin/shmprobe"},
		Stdout:              &stdout,
		Stderr:              &stderr,
		DisableHostLockdown: true,
		Extensions:          []Extension{ext},
	})
	if err != nil {
		if errors.Is(err, ErrPlatformUnavailable) || strings.Contains(err.Error(), "HV_") {
			t.Skipf("HVF unavailable: %v", err)
		}
		t.Fatalf("New: %v", err)
	}

	code, runErr := sb.Run(ctx)
	if runErr != nil || code != 0 {
		_ = sb.Close()
		t.Fatalf("Run: code=%d err=%v stdout=%q stderr=%q", code, runErr, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "SHM_OK") {
		_ = sb.Close()
		t.Fatalf("stdout = %q, want SHM_OK", stdout.String())
	}

	// Host observes guest write directly through the imported zero-copy view.
	got := string(ext.region.Bytes()[64 : 64+len("GUEST_ZERO_COPY_OK")])
	if got != "GUEST_ZERO_COPY_OK" {
		_ = sb.Close()
		t.Fatalf("host view[64:] = %q, want GUEST_ZERO_COPY_OK", got)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ext.region.Unmapped() {
		t.Fatal("imported region stayed mapped after Sandbox.Close")
	}
}
