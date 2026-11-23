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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testimage"
)

func buildGuestCgroup2IOProbeELF(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling guest cgroup2 io probe")
	}
	srcDir := t.TempDir()
	src := `package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

func mustWriteFile(path, data string) {
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
		os.Exit(10)
	}
}

func doDirectWriteAndRead(path string, chunks, chunkSize int) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_TRUNC|syscall.O_DIRECT, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open O_DIRECT %s: %v\n", path, err)
		os.Exit(11)
	}
	defer syscall.Close(fd)
	buf := bytes.Repeat([]byte("A"), chunkSize)
	for range chunks {
		n, err := syscall.Write(fd, buf)
		if err != nil || n != chunkSize {
			fmt.Fprintf(os.Stderr, "write %s: n=%d err=%v\n", path, n, err)
			os.Exit(12)
		}
	}
	if _, err := syscall.Seek(fd, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "seek %s: %v\n", path, err)
		os.Exit(13)
	}
	rbuf := make([]byte, chunkSize)
	for range chunks {
		n, err := syscall.Read(fd, rbuf)
		if err != nil || n != chunkSize {
			fmt.Fprintf(os.Stderr, "read %s: n=%d err=%v\n", path, n, err)
			os.Exit(14)
		}
	}
}

func main() {
	ctrls, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read controllers: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("CONTROLLERS=%s\n", strings.TrimSpace(string(ctrls)))
	mustWriteFile("/sys/fs/cgroup/cgroup.subtree_control", "+io\n")
	for _, d := range []string{"/sys/fs/cgroup/cg-a", "/sys/fs/cgroup/cg-b"} {
		if err := os.Mkdir(d, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", d, err)
			os.Exit(3)
		}
	}

	// Verify io.weight and io.max accept-and-store.
	mustWriteFile("/sys/fs/cgroup/cg-a/io.weight", "default 200\n")
	mustWriteFile("/sys/fs/cgroup/cg-a/io.max", "254:16 wbps=104857600\n")
	wBytes, _ := os.ReadFile("/sys/fs/cgroup/cg-a/io.weight")
	mBytes, _ := os.ReadFile("/sys/fs/cgroup/cg-a/io.max")
	fmt.Printf("WEIGHT=%s\n", strings.TrimSpace(string(wBytes)))
	fmt.Printf("MAX=%s\n", strings.TrimSpace(string(mBytes)))

	// Join cg-a and run three concurrent workers (ext4lite + rootfs overlay) to
	// exercise concurrent overlay/blockdev I/O inside one sandbox under -race.
	mustWriteFile("/sys/fs/cgroup/cg-a/cgroup.procs", strconv.Itoa(os.Getpid())+"\n")
	var wg sync.WaitGroup
	for _, job := range []struct {
		path   string
		chunks int
	}{
		{"/mnt/vol/a.bin", 4},
		{"/root_a.bin", 2},
		{"/root_a2.bin", 1},
	} {
		wg.Add(1)
		go func(p string, c int) {
			defer wg.Done()
			doDirectWriteAndRead(p, c, 1<<20)
		}(job.path, job.chunks)
	}
	wg.Wait()

	// Move to cg-b, write/read 1 MiB on ext4lite (/mnt/vol/b.bin), and read a
	// fresh EROFS lower file (/etc/erofs_blob.bin).
	mustWriteFile("/sys/fs/cgroup/cg-b/cgroup.procs", strconv.Itoa(os.Getpid())+"\n")
	doDirectWriteAndRead("/mnt/vol/b.bin", 1, 1<<20)
	if blob, err := os.ReadFile("/etc/erofs_blob.bin"); err != nil || len(blob) != 128<<10 {
		fmt.Fprintf(os.Stderr, "read erofs_blob: len=%d err=%v\n", len(blob), err)
		os.Exit(17)
	}

	for _, name := range []struct {
		label, path string
	}{
		{"CGA", "/sys/fs/cgroup/cg-a/io.stat"},
		{"CGB", "/sys/fs/cgroup/cg-b/io.stat"},
		{"ROOT", "/sys/fs/cgroup/io.stat"},
	} {
		raw, err := os.ReadFile(name.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", name.path, err)
			os.Exit(4)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line != "" {
				fmt.Printf("%s %s\n", name.label, line)
			}
		}
	}
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module ioprobe\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "ioprobe")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest ioprobe: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read ioprobe: %v", err)
	}
	return data
}

func parseIOStatKV(t *testing.T, line string) map[string]uint64 {
	t.Helper()
	m := make(map[string]uint64)
	for _, field := range strings.Fields(line) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("parse %q in %q: %v", field, line, err)
		}
		m[k] = n
	}
	return m
}

func TestCgroup2IOAccountingGuestEndToEndAndMultiSandboxIsolation(t *testing.T) {
	requireCheckpointGuestBackend(t)

	probeELF := buildGuestCgroup2IOProbeELF(t)
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/ioprobe", Data: probeELF, Mode: 0o755},
		testimage.File{Name: "etc/erofs_blob.bin", Data: bytes.Repeat([]byte("E"), 128<<10), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "cg2io", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/ioprobe"},
	})

	runOne := func(name string) (string, error) {
		volPath := filepath.Join(t.TempDir(), name+".ext4")
		var outB, errB bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		sb, err := New(ctx, Config{
			Name:                   name,
			Platform:               PlatformAuto,
			AllowUnconfinedSystrap: runtime.GOOS == "windows",
			OCIImage:               "cg2io:latest",
			RegistryBaseURL:        regURL,
			OCICacheDir:            t.TempDir(),
			NetworkMode:            NetModeNone,
			DisableHostLockdown:    true,
			Mounts: []Mount{{
				Kind:      MountVolume,
				ImagePath: volPath,
				GuestPath: "/mnt/vol",
			}},
			Envv:   []string{"GODEBUG=asyncpreemptoff=1", "GOMAXPROCS=2"},
			Stdout: &outB,
			Stderr: &errB,
		})
		if err != nil {
			return "", err
		}
		defer sb.Close()
		code, err := sb.Run(ctx)
		if err != nil || code != 0 {
			return outB.String(), fmt.Errorf("exit=%d err=%v stderr=%q", code, err, errB.String())
		}
		return outB.String(), nil
	}

	// Run two sandboxes concurrently in the same host process to verify per-sandbox
	// VFS/blockdev/cgroup2fs state never bleeds across sandboxes.
	var (
		wg   sync.WaitGroup
		outs [2]string
		errs [2]error
	)
	wg.Add(2)
	for i, name := range []string{"cg2io-sb1", "cg2io-sb2"} {
		go func(idx int, nm string) {
			defer wg.Done()
			outs[idx], errs[idx] = runOne(nm)
		}(i, name)
	}
	wg.Wait()
	for idx, err := range errs {
		if err != nil {
			t.Fatalf("sb%d failed: %v\nstdout:\n%s", idx, err, outs[idx])
		}
	}

	for idx, out := range outs {
		if !strings.Contains(out, "CONTROLLERS=") || !strings.Contains(out, "io") {
			t.Fatalf("sb%d missing io controller:\n%s", idx, out)
		}
		if !strings.Contains(out, "WEIGHT=default 200") || !strings.Contains(out, "MAX=254:16 rbps=max wbps=104857600 riops=max wiops=max") {
			t.Fatalf("sb%d weight/max mismatch:\n%s", idx, out)
		}

		lines := make(map[string]map[string]uint64)
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			if fields[0] == "CGA" || fields[0] == "CGB" || fields[0] == "ROOT" {
				lines[fields[0]+" "+fields[1]] = parseIOStatKV(t, line)
			}
		}

		// cg-a ext4lite (254:16): 4 MiB written, 4 MiB read, >= 4 ios each.
		cgaVol := lines["CGA 254:16"]
		if cgaVol["wbytes"] != 4<<20 || cgaVol["rbytes"] != 4<<20 || cgaVol["wios"] != 4 || cgaVol["rios"] != 4 {
			t.Fatalf("sb%d CGA 254:16 = %v, want wbytes=4MiB rbytes=4MiB wios=4 rios=4\nfull:\n%s", idx, cgaVol, out)
		}
		// cg-a rootfs overlay (254:0): 3 MiB written (2 MiB + 1 MiB concurrent), >= 3 MiB read.
		cgaRoot := lines["CGA 254:0"]
		if cgaRoot["wbytes"] != 3<<20 || cgaRoot["rbytes"] < 3<<20 || cgaRoot["wios"] != 3 {
			t.Fatalf("sb%d CGA 254:0 = %v, want wbytes=3MiB rbytes>=3MiB wios=3\nfull:\n%s", idx, cgaRoot, out)
		}
		// cg-b ext4lite (254:16): exactly 1 MiB written & read (isolated from cg-a and from the other sandbox!).
		cgbVol := lines["CGB 254:16"]
		if cgbVol["wbytes"] != 1<<20 || cgbVol["rbytes"] != 1<<20 || cgbVol["wios"] != 1 || cgbVol["rios"] != 1 {
			t.Fatalf("sb%d CGB 254:16 = %v, want wbytes=1MiB rbytes=1MiB wios=1 rios=1\nfull:\n%s", idx, cgbVol, out)
		}
		// cg-b EROFS lower read (254:0): >= 128 KiB read, 0 written.
		cgbRoot := lines["CGB 254:0"]
		if cgbRoot["rbytes"] < 128<<10 || cgbRoot["wbytes"] != 0 {
			t.Fatalf("sb%d CGB 254:0 = %v, want rbytes>=128KiB wbytes=0\nfull:\n%s", idx, cgbRoot, out)
		}
		// Root aggregates cg-a + cg-b = exactly 5 MiB on 254:16 (no cross-sandbox bleed!).
		rootVol := lines["ROOT 254:16"]
		if rootVol["wbytes"] != 5<<20 || rootVol["rbytes"] != 5<<20 || rootVol["wios"] != 5 || rootVol["rios"] != 5 {
			t.Fatalf("sb%d ROOT 254:16 = %v, want wbytes=5MiB rbytes=5MiB wios=5 rios=5\nfull:\n%s", idx, rootVol, out)
		}
	}

	// Verify RootVolume (ext4lite upper on rootfs overlay) does NOT double-count
	// writes on 254:0 (only 254:16 ext4lite upper and 254:32 /mnt/vol should count writes).
	var rvOut, rvErr bytes.Buffer
	rvCtx, rvCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer rvCancel()
	rvSB, err := New(rvCtx, Config{
		Name:                   "cg2io-rootvol",
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		OCIImage:               "cg2io:latest",
		RegistryBaseURL:        regURL,
		OCICacheDir:            t.TempDir(),
		RootVolume:             filepath.Join(t.TempDir(), "rootvol.ext4"),
		NetworkMode:            NetModeNone,
		DisableHostLockdown:    true,
		Mounts: []Mount{{
			Kind:      MountVolume,
			ImagePath: filepath.Join(t.TempDir(), "vol.ext4"),
			GuestPath: "/mnt/vol",
		}},
		Stdout: &rvOut,
		Stderr: &rvErr,
	})
	if err != nil {
		t.Fatalf("New(rootvol): %v", err)
	}
	defer rvSB.Close()
	if code, err := rvSB.Run(rvCtx); err != nil || code != 0 {
		t.Fatalf("Run(rootvol) = (%d, %v)\nstdout:\n%s\nstderr:\n%s", code, err, rvOut.String(), rvErr.String())
	}
	rvLines := make(map[string]map[string]uint64)
	for _, line := range strings.Split(strings.TrimSpace(rvOut.String()), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && (fields[0] == "CGA" || fields[0] == "CGB" || fields[0] == "ROOT") {
			rvLines[fields[0]+" "+fields[1]] = parseIOStatKV(t, line)
		}
	}
	// With RootVolume: 254:0 is EROFS lower (0 writes!), 254:16 is RootVolume upper (3 MiB written), 254:32 is /mnt/vol (4 MiB written in cg-a).
	if rvLines["CGA 254:0"]["wbytes"] != 0 {
		t.Fatalf("rootvol CGA 254:0 wbytes = %d, want 0 (double-counting regression)\n%s", rvLines["CGA 254:0"]["wbytes"], rvOut.String())
	}
	if rvLines["CGA 254:16"]["wbytes"] != 3<<20 || rvLines["CGA 254:32"]["wbytes"] != 4<<20 {
		t.Fatalf("rootvol CGA upper/vol mismatch: 254:16=%v 254:32=%v\n%s", rvLines["CGA 254:16"], rvLines["CGA 254:32"], rvOut.String())
	}
}
