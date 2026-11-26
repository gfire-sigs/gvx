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

package rungvx

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx"
)

func TestImageGroupAndGoTemplateFormatting(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)

	runCLIArgs(t, nil, "image", "pull", "-cache-dir", env.cacheDir, reg.ref("v1")).mustSucceed(t, "image pull")

	lsOut := runCLIArgs(t, nil, "image", "ls", "-cache-dir", env.cacheDir, "--format", `table {{.Repository}}\t{{.Tag}}`).mustSucceed(t, "image ls template").stdout
	if !strings.Contains(lsOut, reg.Host+"/gvx/app") || !strings.Contains(lsOut, "v1") {
		t.Fatalf("image ls template output = %q", lsOut)
	}

	inspectOut := runCLIArgs(t, nil, "image", "inspect", reg.ref("v1"), "-cache-dir", env.cacheDir, "-f", "{{.Architecture}}:{{join .Config.Cmd \",\"}}").mustSucceed(t, "image inspect -f").stdout
	if !strings.Contains(inspectOut, ":/bin/true") {
		t.Fatalf("image inspect -f output = %q, want :/bin/true", inspectOut)
	}

	// Declining confirmation leaves the image intact.
	declined := runCLIArgs(t, strings.NewReader("n\n"), "image", "prune", "-a", "-cache-dir", env.cacheDir).mustSucceed(t, "image prune declined")
	if len(env.imageIDs()) != 1 {
		t.Fatalf("image prune without y deleted images: %q", declined.stdout)
	}

	pruned := runCLIArgs(t, nil, "image", "prune", "-af", "-cache-dir", env.cacheDir).mustSucceed(t, "image prune -af")
	if !strings.Contains(pruned.stdout, "Total reclaimed space:") || len(env.imageIDs()) != 0 {
		t.Fatalf("image prune -af stdout = %q, remaining IDs = %v", pruned.stdout, env.imageIDs())
	}
}

func TestVolumeCLICommands(t *testing.T) {
	env := newCLIEnv(t)

	created := runCLIArgs(t, nil, "volume", "create", "dbdata", "-cache-dir", env.cacheDir).mustSucceed(t, "volume create dbdata")
	if strings.TrimSpace(created.stdout) != "dbdata" {
		t.Fatalf("volume create stdout = %q, want dbdata", created.stdout)
	}
	runCLIArgs(t, nil, "volume", "create", "logs", "-d", "hostfs", "-cache-dir", env.cacheDir).mustSucceed(t, "volume create hostfs")

	lsQuiet := runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir).mustSucceed(t, "volume ls -q")
	if got := strings.Fields(lsQuiet.stdout); len(got) != 2 || got[0] != "dbdata" || got[1] != "logs" {
		t.Fatalf("volume ls -q = %v, want [dbdata logs]", got)
	}

	inspJSON := runCLIArgs(t, nil, "volume", "inspect", "dbdata", "-cache-dir", env.cacheDir).mustSucceed(t, "volume inspect")
	var items []gvx.VolumeInfo
	if err := json.Unmarshal([]byte(inspJSON.stdout), &items); err != nil || len(items) != 1 {
		t.Fatalf("volume inspect JSON = %q, err = %v", inspJSON.stdout, err)
	}

	runCLIArgs(t, strings.NewReader("n\n"), "volume", "prune", "-cache-dir", env.cacheDir).mustSucceed(t, "volume prune declined")
	if got := strings.Fields(runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir).stdout); len(got) != 2 {
		t.Fatalf("volumes after declined prune = %v, want 2", got)
	}

	runCLIArgs(t, nil, "volume", "rm", "logs", "-cache-dir", env.cacheDir).mustSucceed(t, "volume rm logs")
	missing := runCLIArgs(t, nil, "volume", "rm", "logs", "-cache-dir", env.cacheDir)
	if missing.code != 1 {
		t.Fatalf("volume rm missing exited %d, want 1", missing.code)
	}
	runCLIArgs(t, nil, "volume", "rm", "-f", "logs", "-cache-dir", env.cacheDir).mustSucceed(t, "volume rm -f missing")

	runCLIArgs(t, nil, "volume", "prune", "-f", "-cache-dir", env.cacheDir).mustSucceed(t, "volume prune -f")
	if got := strings.Fields(runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir).stdout); len(got) != 0 {
		t.Fatalf("volumes after prune -f = %v, want empty", got)
	}
}

func TestVolumeCLIRefusesRemovingMountedSandboxVolume(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "cat.elf")
	if err := os.WriteFile(elfPath, catELF, 0o755); err != nil {
		t.Fatal(err)
	}

	env := newCLIEnv(t)
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "ready.txt"), []byte("mounted-ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runCLIArgs(t, nil, "volume", "create", "dbdata", "-cache-dir", env.cacheDir).mustSucceed(t, "volume create dbdata")

	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()
	stdout := newSyncNotifyBuffer()
	stderr := newSyncNotifyBuffer()
	done := make(chan int, 1)

	go func() {
		done <- executeCLI(
			context.Background(),
			[]string{
				"run",
				"-lockdown=false",
				"-backend=" + platform,
				"-net=none",
				"-cache-dir=" + env.cacheDir,
				"-workspace=" + wsDir,
				"-v=dbdata:/data",
				"-bin=" + elfPath,
				"--",
				"/workspace/ready.txt",
				"/proc/self/fd/0",
			},
			stdinR,
			stdout,
			stderr,
		)
	}()

	stdout.waitForSubstring(t, "mounted-ok\n", 15*time.Second)

	inUseOut := runCLIArgs(t, nil, "volume", "inspect", "dbdata", "-cache-dir", env.cacheDir, "-f", "{{.InUse}}").mustSucceed(t, "volume inspect InUse")
	if strings.TrimSpace(inUseOut.stdout) != "true" {
		t.Fatalf("volume inspect InUse = %q, want true", inUseOut.stdout)
	}

	rmLocked := runCLIArgs(t, nil, "volume", "rm", "-f", "dbdata", "-cache-dir", env.cacheDir)
	if rmLocked.code != 1 || !strings.Contains(rmLocked.stderr, "in use") {
		t.Fatalf("volume rm locked = (%d, %q), want exit 1 mentioning in use", rmLocked.code, rmLocked.stderr)
	}

	_ = stdinW.Close()
	if code := <-done; code != 0 {
		t.Fatalf("sandbox exited with %d: %s", code, stderr.String())
	}
	runCLIArgs(t, nil, "volume", "rm", "dbdata", "-cache-dir", env.cacheDir).mustSucceed(t, "volume rm after sandbox exit")
}

func TestSystemInfoDFPruneAndCompletionCommands(t *testing.T) {
	env := newCLIEnv(t)
	runCLIArgs(t, nil, "volume", "create", "sysvol", "-cache-dir", env.cacheDir).mustSucceed(t, "volume create")

	infoJSON := runCLIArgs(t, nil, "info", "--format", "json", "-cache-dir", env.cacheDir).mustSucceed(t, "rungvx info json")
	var si gvx.SystemInfo
	if err := json.Unmarshal([]byte(infoJSON.stdout), &si); err != nil {
		t.Fatalf("unmarshal info json: %v\n%s", err, infoJSON.stdout)
	}
	if si.Volumes != 1 {
		t.Fatalf("info Volumes = %d, want 1", si.Volumes)
	}

	infoTable := runCLIArgs(t, nil, "info", "--format", `table {{.OS}}\t{{.Volumes}}`, "-cache-dir", env.cacheDir).mustSucceed(t, "rungvx info table template")
	if strings.Contains(infoTable.stdout, `\t`) || !strings.Contains(infoTable.stdout, runtime.GOOS) {
		t.Fatalf("info table template output = %q", infoTable.stdout)
	}
	if badInspect := runCLIArgs(t, nil, "volume", "inspect", "--format", "table", "sysvol", "-cache-dir", env.cacheDir); badInspect.code != 2 {
		t.Fatalf("volume inspect --format table exited %d, want 2 (stderr: %s)", badInspect.code, badInspect.stderr)
	}

	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	reg := startRegistryForArch(t, otherArch, twoFiles()...)
	runCLIArgs(t, nil, "pull", "--platform", "linux/"+otherArch, "-cache-dir", env.cacheDir, reg.ref("v1")).mustSucceed(t, "pull foreign arch")

	dfOut := runCLIArgs(t, nil, "system", "df", "-v", "-cache-dir", env.cacheDir).mustSucceed(t, "system df -v").stdout
	for _, want := range []string{"TYPE", "Images", "Local Volumes", "sysvol", otherArch} {
		if !strings.Contains(dfOut, want) {
			t.Errorf("system df -v lacks %q:\n%s", want, dfOut)
		}
	}

	runCLIArgs(t, nil, "system", "prune", "-af", "--volumes", "-cache-dir", env.cacheDir).mustSucceed(t, "system prune -af --volumes")
	if rem := strings.Fields(runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir).stdout); len(rem) != 0 {
		t.Fatalf("volumes after system prune --volumes = %v, want empty", rem)
	}
	if remImgs := strings.Fields(runCLIArgs(t, nil, "images", "-aq", "-arch", otherArch, "-cache-dir", env.cacheDir).stdout); len(remImgs) != 0 {
		t.Fatalf("foreign-arch images after multi-arch system prune = %v, want empty", remImgs)
	}

	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		comp := runCLIArgs(t, nil, "completion", sh).mustSucceed(t, "completion "+sh)
		if !strings.Contains(comp.stdout, "rungvx") || !strings.Contains(comp.stdout, "volume") || !strings.Contains(comp.stdout, "volume-dir") {
			t.Errorf("completion %s output missing expected tokens:\n%s", sh, comp.stdout)
		}
	}
	bad := runCLIArgs(t, nil, "completion", "csh")
	if bad.code != 2 {
		t.Errorf("completion csh exited %d, want 2", bad.code)
	}
}

func TestRootfsVolumeWithVolumeAndSystemCLICommands(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "ready.txt", Data: []byte("rootfs-ready\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "gvx/rootcat", "v1", testimage.Image{
		Arch:   runtime.GOARCH,
		Layers: [][]byte{layer},
	})
	parsedURL, err := url.Parse(regURL)
	if err != nil {
		t.Fatal(err)
	}
	imageRef := parsedURL.Host + "/gvx/rootcat:v1"

	env := newCLIEnv(t)
	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()
	stdout := newSyncNotifyBuffer()
	stderr := newSyncNotifyBuffer()
	done := make(chan int, 1)

	go func() {
		done <- executeCLI(
			context.Background(),
			[]string{
				"run",
				"-lockdown=false",
				"-backend=" + platform,
				"-net=none",
				"-cache-dir=" + env.cacheDir,
				"-rootfs-volume=rootcli",
				imageRef,
				"/bin/cat",
				"/ready.txt",
				"/proc/self/fd/0",
			},
			stdinR,
			stdout,
			stderr,
		)
	}()

	stdout.waitForSubstring(t, "rootfs-ready\n", 45*time.Second)

	lsOut := runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir).mustSucceed(t, "volume ls -q")
	if strings.TrimSpace(lsOut.stdout) != "rootcli" {
		t.Fatalf("volume ls -q = %q, want rootcli", lsOut.stdout)
	}

	inspOut := runCLIArgs(t, nil, "volume", "inspect", "rootcli", "-cache-dir", env.cacheDir, "-f", "{{.Driver}}:{{.InUse}}").mustSucceed(t, "volume inspect")
	if strings.TrimSpace(inspOut.stdout) != "ext4lite:true" {
		t.Fatalf("volume inspect = %q, want ext4lite:true", inspOut.stdout)
	}

	dfOut := runCLIArgs(t, nil, "system", "df", "-v", "-cache-dir", env.cacheDir).mustSucceed(t, "system df -v").stdout
	if !strings.Contains(dfOut, "Local Volumes") || !strings.Contains(dfOut, "rootcli") {
		t.Fatalf("system df -v missing rootcli:\n%s", dfOut)
	}

	rmLocked := runCLIArgs(t, nil, "volume", "rm", "-f", "rootcli", "-cache-dir", env.cacheDir)
	if rmLocked.code != 1 || !strings.Contains(rmLocked.stderr, "in use") {
		t.Fatalf("volume rm locked = (%d, %q), want exit 1 mentioning in use", rmLocked.code, rmLocked.stderr)
	}

	_ = stdinW.Close()
	if code := <-done; code != 0 {
		t.Fatalf("sandbox exited with %d: %s", code, stderr.String())
	}

	inspAfter := runCLIArgs(t, nil, "volume", "inspect", "rootcli", "-cache-dir", env.cacheDir, "-f", "{{.InUse}}").mustSucceed(t, "volume inspect after exit")
	if strings.TrimSpace(inspAfter.stdout) != "false" {
		t.Fatalf("volume inspect after exit = %q, want false", inspAfter.stdout)
	}
	runCLIArgs(t, nil, "volume", "rm", "rootcli", "-cache-dir", env.cacheDir).mustSucceed(t, "volume rm after exit")
}

func TestVolumeCompactAndAllocatedBytesCLI(t *testing.T) {
	// Property: `rungvx volume ls --format json` and `rungvx volume inspect` emit SizeBytes, AllocatedBytes,
	// InUse, and LockMode without breaking `-q`, and `rungvx volume compact` compacts unlocked ext4lite volumes
	// while failing with exit 1 on missing/in-use volumes and exit 2 on missing arguments.
	env := newCLIEnv(t)

	runCLIArgs(t, nil, "volume", "create", "compactme", "-cache-dir", env.cacheDir).mustSucceed(t, "volume create compactme")
	viBefore, err := gvx.InspectVolume(env.cacheDir, "compactme")
	if err != nil {
		t.Fatalf("InspectVolume(compactme): %v", err)
	}
	initialSize := viBefore.SizeBytes
	if err := os.Truncate(viBefore.Mountpoint, initialSize+(48<<20)); err != nil {
		t.Fatalf("Truncate: %v", err)
	}

	lsJSON := runCLIArgs(t, nil, "volume", "ls", "--format", "json", "-cache-dir", env.cacheDir).mustSucceed(t, "volume ls --format json")
	var row struct {
		Name           string `json:"Name"`
		Driver         string `json:"Driver"`
		SizeBytes      int64  `json:"SizeBytes"`
		AllocatedBytes int64  `json:"AllocatedBytes"`
		InUse          bool   `json:"InUse"`
		LockMode       string `json:"LockMode"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(lsJSON.stdout)), &row); err != nil {
		t.Fatalf("unmarshal volume ls json %q: %v", lsJSON.stdout, err)
	}
	if row.Name != "compactme" || row.SizeBytes != initialSize+(48<<20) || row.AllocatedBytes <= 0 || row.AllocatedBytes >= row.SizeBytes/2 || row.InUse || row.LockMode != "none" {
		t.Fatalf("volume ls json row = %+v", row)
	}

	lsTable := runCLIArgs(t, nil, "volume", "ls", "-cache-dir", env.cacheDir).mustSucceed(t, "volume ls table")
	if !strings.Contains(lsTable.stdout, "ALLOCATED") || !strings.Contains(lsTable.stdout, "compactme") {
		t.Fatalf("volume ls table = %q, want ALLOCATED column and compactme", lsTable.stdout)
	}

	if noArgs := runCLIArgs(t, nil, "volume", "compact", "-cache-dir", env.cacheDir); noArgs.code != 2 {
		t.Fatalf("volume compact with no args exited %d, want 2", noArgs.code)
	}
	if missing := runCLIArgs(t, nil, "volume", "compact", "missingvol", "-cache-dir", env.cacheDir); missing.code != 1 || !strings.Contains(missing.stderr, "no such volume") {
		t.Fatalf("volume compact missing = (%d, %q), want exit 1 mentioning no such volume", missing.code, missing.stderr)
	}

	compactedOut := runCLIArgs(t, nil, "volume", "compact", "compactme", "-cache-dir", env.cacheDir).mustSucceed(t, "volume compact compactme")
	if strings.TrimSpace(compactedOut.stdout) != "compactme" {
		t.Fatalf("volume compact stdout = %q, want compactme", compactedOut.stdout)
	}

	inspJSON := runCLIArgs(t, nil, "volume", "inspect", "compactme", "-cache-dir", env.cacheDir).mustSucceed(t, "volume inspect compactme")
	var items []gvx.VolumeInfo
	if err := json.Unmarshal([]byte(inspJSON.stdout), &items); err != nil || len(items) != 1 {
		t.Fatalf("volume inspect json = %q, err = %v", inspJSON.stdout, err)
	}
	if items[0].SizeBytes != initialSize || items[0].LockMode != "none" || items[0].InUse {
		t.Fatalf("inspected after compact = %+v, want SizeBytes=%d LockMode=none InUse=false", items[0], initialSize)
	}
}

func TestVolumeAndSystemCLIVolumeDirFlag(t *testing.T) {
	canaryDir := t.TempDir()
	t.Setenv(gvx.VolumeDirEnv, canaryDir)
	if _, err := gvx.CreateVolume("", "canary", gvx.DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume(canary): %v", err)
	}

	env := newCLIEnv(t)
	volDir := t.TempDir()

	runCLIArgs(t, nil, "volume", "create", "db", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume create -volume-dir")
	if _, err := os.Stat(filepath.Join(volDir, "db.ext4")); err != nil {
		t.Fatalf("expected %s/db.ext4: %v", volDir, err)
	}
	if _, err := os.Lstat(filepath.Join(env.cacheDir, "volumes")); !os.IsNotExist(err) {
		t.Fatalf("cacheDir/volumes should not exist when -volume-dir is set: %v", err)
	}

	lsOut := runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume ls -volume-dir")
	if got := strings.Fields(lsOut.stdout); len(got) != 1 || got[0] != "db" {
		t.Fatalf("volume ls -q = %v, want [db]", got)
	}

	inspOut := runCLIArgs(t, nil, "volume", "inspect", "db", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume inspect -volume-dir")
	var items []gvx.VolumeInfo
	if err := json.Unmarshal([]byte(inspOut.stdout), &items); err != nil || len(items) != 1 {
		t.Fatalf("volume inspect JSON = %q, err = %v", inspOut.stdout, err)
	}
	if filepath.Dir(items[0].Mountpoint) != volDir {
		t.Fatalf("inspect Mountpoint = %q, want under %q", items[0].Mountpoint, volDir)
	}

	runCLIArgs(t, nil, "volume", "compact", "db", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume compact -volume-dir")

	infoOut := runCLIArgs(t, nil, "info", "--format", "json", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "info -volume-dir")
	var si gvx.SystemInfo
	if err := json.Unmarshal([]byte(infoOut.stdout), &si); err != nil {
		t.Fatalf("unmarshal info json: %v\n%s", err, infoOut.stdout)
	}
	if si.VolumeDir != volDir || si.Volumes != 1 {
		t.Fatalf("info = (VolumeDir=%q, Volumes=%d), want (%q, 1)", si.VolumeDir, si.Volumes, volDir)
	}

	dfOut := runCLIArgs(t, nil, "system", "df", "-v", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "system df -volume-dir").stdout
	if !strings.Contains(dfOut, "db") || strings.Contains(dfOut, "canary") {
		t.Fatalf("system df -v = %q, want db and not canary", dfOut)
	}

	runCLIArgs(t, nil, "volume", "rm", "db", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume rm -volume-dir")

	runCLIArgs(t, nil, "volume", "create", "tmpv", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume create tmpv")
	runCLIArgs(t, nil, "volume", "prune", "-f", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume prune -volume-dir")
	if got := strings.Fields(runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir, "-volume-dir", volDir).stdout); len(got) != 0 {
		t.Fatalf("volumes after volume prune -f = %v, want empty", got)
	}

	runCLIArgs(t, nil, "volume", "create", "tmpv2", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "volume create tmpv2")
	runCLIArgs(t, nil, "system", "prune", "-af", "--volumes", "-cache-dir", env.cacheDir, "-volume-dir", volDir).mustSucceed(t, "system prune -volume-dir")
	if got := strings.Fields(runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir, "-volume-dir", volDir).stdout); len(got) != 0 {
		t.Fatalf("volumes after system prune --volumes = %v, want empty", got)
	}

	if _, err := gvx.InspectVolume("", "canary"); err != nil {
		t.Fatalf("canary volume in %s was affected: %v", gvx.VolumeDirEnv, err)
	}
}
