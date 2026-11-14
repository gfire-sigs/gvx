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
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

func TestRunFlagsShortValueClustersAndGuestIsolation(t *testing.T) {
	rc, _, done, stderr := parse(t,
		"-itp", "8080:80",
		"-p9090:90/udp",
		"-eFOO=bar",
		"-u1000:1000",
		"-w/app",
		"-m256m",
		"alpine:3.20",
		"-it", "-p", "ignored-by-host",
	)
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	cfg := rc.cfg
	if !cfg.TTY {
		t.Errorf("TTY = false, want true from -itp")
	}
	if len(cfg.PortForwards) != 2 || cfg.PortForwards[0].HostPort != 8080 || cfg.PortForwards[1].HostPort != 9090 {
		t.Errorf("PortForwards = %+v, want 8080->80 and 9090->90/udp", cfg.PortForwards)
	}
	if !reflect.DeepEqual(cfg.Envv, []string{"FOO=bar"}) {
		t.Errorf("Envv = %q, want [FOO=bar]", cfg.Envv)
	}
	if cfg.User != "1000:1000" || cfg.WorkDir != "/app" || cfg.Resources.MemoryBytes != 256<<20 {
		t.Errorf("user=%q workdir=%q mem=%d", cfg.User, cfg.WorkDir, cfg.Resources.MemoryBytes)
	}
	if wantCmd := []string{"-it", "-p", "ignored-by-host"}; !reflect.DeepEqual(cfg.Cmd, wantCmd) {
		t.Errorf("Cmd = %q, want %q", cfg.Cmd, wantCmd)
	}
}

func TestRunFlagsBackendAndPlatformOrthogonality(t *testing.T) {
	rc, _, done, stderr := parse(t, "--platform", "linux/arm64", "--backend", "systrap", "alpine:3.20")
	if done {
		t.Fatalf("parseRunArgs failed: %s", stderr)
	}
	if rc.cfg.Architecture != "arm64" || rc.cfg.Platform != gvx.PlatformSystrap || rc.autoPlatform {
		t.Errorf("got arch=%q platform=%q auto=%v, want arm64/systrap/false", rc.cfg.Architecture, rc.cfg.Platform, rc.autoPlatform)
	}

	rcAuto, _, doneAuto, stderrAuto := parse(t, "--platform", "linux/amd64", "--backend", "auto", "alpine:3.20")
	if doneAuto {
		t.Fatalf("parseRunArgs auto failed: %s", stderrAuto)
	}
	if rcAuto.cfg.Architecture != "amd64" || rcAuto.cfg.Platform != gvx.PlatformAuto || !rcAuto.autoPlatform {
		t.Errorf("got arch=%q platform=%q auto=%v, want amd64/auto/true", rcAuto.cfg.Architecture, rcAuto.cfg.Platform, rcAuto.autoPlatform)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown backend", []string{"--backend=kvm", "-image=x"}, "--backend"},
		{"unknown platform backend", []string{"--platform=kvm", "-image=x"}, "--platform"},
		{"conflicting backend and platform", []string{"--platform=whpx", "--backend=systrap", "-image=x"}, "conflicts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code, stop, errOut := parse(t, tc.args...)
			if !stop || code != 2 || !strings.Contains(errOut, tc.want) {
				t.Fatalf("parse(%v) = (code %d, stop %v, stderr %q), want exit 2 containing %q", tc.args, code, stop, errOut, tc.want)
			}
		})
	}
}

func TestManagementCommandsAcceptTrailingFlagsAndShortClusters(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)

	// Trailing --platform on pull.
	env.run("pull", reg.ref("v1"), "--platform", "linux/"+runtime.GOARCH).mustSucceed(t, "pull with trailing --platform")

	// Trailing clustered -aq on images after positional filter.
	ids := strings.TrimSpace(env.run("images", reg.Host+"/gvx/app", "-aq").mustSucceed(t, "images NAME -aq").stdout)
	if !shortID.MatchString(ids) {
		t.Fatalf("images NAME -aq = %q, want 12-hex ID", ids)
	}

	// Trailing -oFILE attached short flag on save.
	archivePath := filepath.Join(t.TempDir(), "saved.tar")
	env.run("save", reg.ref("v1"), "-o"+archivePath).mustSucceed(t, "save with trailing -oFILE")

	// Trailing -f on rmi after tagging a second name.
	env.run("tag", reg.ref("v1"), "copy:v1").mustSucceed(t, "tag copy:v1")
	env.run("rmi", ids, "-f").mustSucceed(t, "rmi ID -f")
}
