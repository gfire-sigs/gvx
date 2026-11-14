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

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
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

	infoJSON := runCLIArgs(t, nil, "info", "--format", "json", "-cache-dir", env.cacheDir).mustSucceed(t, "rungv info json")
	var si gvx.SystemInfo
	if err := json.Unmarshal([]byte(infoJSON.stdout), &si); err != nil {
		t.Fatalf("unmarshal info json: %v\n%s", err, infoJSON.stdout)
	}
	if si.Volumes != 1 {
		t.Fatalf("info Volumes = %d, want 1", si.Volumes)
	}

	dfOut := runCLIArgs(t, nil, "system", "df", "-v", "-cache-dir", env.cacheDir).mustSucceed(t, "system df -v").stdout
	for _, want := range []string{"TYPE", "Images", "Local Volumes", "sysvol"} {
		if !strings.Contains(dfOut, want) {
			t.Errorf("system df -v lacks %q:\n%s", want, dfOut)
		}
	}

	runCLIArgs(t, nil, "system", "prune", "-af", "--volumes", "-cache-dir", env.cacheDir).mustSucceed(t, "system prune -af --volumes")
	if rem := strings.Fields(runCLIArgs(t, nil, "volume", "ls", "-q", "-cache-dir", env.cacheDir).stdout); len(rem) != 0 {
		t.Fatalf("volumes after system prune --volumes = %v, want empty", rem)
	}

	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		comp := runCLIArgs(t, nil, "completion", sh).mustSucceed(t, "completion "+sh)
		if !strings.Contains(comp.stdout, "rungv") || !strings.Contains(comp.stdout, "volume") {
			t.Errorf("completion %s output missing expected tokens:\n%s", sh, comp.stdout)
		}
	}
	bad := runCLIArgs(t, nil, "completion", "csh")
	if bad.code != 2 {
		t.Errorf("completion csh exited %d, want 2", bad.code)
	}
}
