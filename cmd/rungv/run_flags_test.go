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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

func TestRunFlagsEnvironmentOrder(t *testing.T) {
	t.Setenv("FROM_HOST", "host-value")
	envFile := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(envFile, []byte("A=file\nB=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, _, done, stderr := parse(t, "--env-file", envFile, "-e", "B=flag", "--env", "FROM_HOST", "-e", "NOT_SET_ANYWHERE_XYZ", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	want := []string{"A=file", "B=file", "B=flag", "FROM_HOST=host-value"}
	if !reflect.DeepEqual(rc.cfg.Envv, want) {
		t.Errorf("Envv = %q, want %q (file lines first, then -e in order, an unset host variable dropped)", rc.cfg.Envv, want)
	}
}

func TestRunFlagsEntrypointAndCommand(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           []string
		wantEntrypoint []string
		wantSet        bool
		wantCmd        []string
	}{
		{"no override", []string{"-image=x", "--", "echo", "hi"}, nil, false, []string{"echo", "hi"}},
		{"override", []string{"--entrypoint", "/bin/sh", "-image=x", "--", "-c", "id"}, []string{"/bin/sh"}, true, []string{"-c", "id"}},
		{"empty override clears", []string{"--entrypoint=", "-image=x"}, nil, true, nil},
		{"image then arguments without a separator", []string{"alpine", "echo", "hi"}, nil, false, []string{"echo", "hi"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, done, stderr := parse(t, tc.args...)
			if done {
				t.Fatalf("parseRunArgs ended the command: %s", stderr)
			}
			cfg := rc.cfg
			if cfg.EntrypointSet != tc.wantSet || !reflect.DeepEqual(cfg.Entrypoint, tc.wantEntrypoint) || !reflect.DeepEqual(cfg.Cmd, tc.wantCmd) {
				t.Errorf("(Entrypoint, EntrypointSet, Cmd) = (%q, %v, %q), want (%q, %v, %q)",
					cfg.Entrypoint, cfg.EntrypointSet, cfg.Cmd, tc.wantEntrypoint, tc.wantSet, tc.wantCmd)
			}
		})
	}
}

func TestRunFlagsForAnELFBinaryUseArgv(t *testing.T) {
	rc, _, done, stderr := parse(t, "-bin=/tmp/app", "--", "-x", "1")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	if !reflect.DeepEqual(rc.cfg.Argv, []string{"-x", "1"}) || len(rc.cfg.Cmd) != 0 {
		t.Errorf("(Argv, Cmd) = (%q, %q), want the arguments in Argv only", rc.cfg.Argv, rc.cfg.Cmd)
	}
}

func TestRunFlagsDockerShortAndLongNames(t *testing.T) {
	rc, _, done, stderr := parse(t,
		"-u", "bob:staff", "-h", "box", "--name", "web-1", "-w", "/srv", "-m", "256m", "--cpus", "1",
		"--network", "bridge", "--publish", "8080:80", "-P", "--rm", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	cfg := rc.cfg
	if cfg.User != "bob:staff" || cfg.Hostname != "box" || cfg.Name != "web-1" || cfg.WorkDir != "/srv" {
		t.Errorf("identity settings = user %q hostname %q name %q workdir %q", cfg.User, cfg.Hostname, cfg.Name, cfg.WorkDir)
	}
	if cfg.Resources != (gvx.Resources{MemoryBytes: 256 << 20, CPUMillis: 1000}) {
		t.Errorf("Resources = %+v, want 256 MiB and 1000 milli-CPUs", cfg.Resources)
	}
	if cfg.NetworkMode != gvx.NetModeNAT || !cfg.PublishAll || len(cfg.PortForwards) != 1 || cfg.PortForwards[0].HostPort != 8080 {
		t.Errorf("network settings = %q publishAll %v forwards %+v", cfg.NetworkMode, cfg.PublishAll, cfg.PortForwards)
	}
}

func TestRunFlagsClusterOfShortFlags(t *testing.T) {
	rc, _, done, stderr := parse(t, "-it", "-image=x")
	if done || !rc.cfg.TTY {
		t.Fatalf("-it: done=%v TTY=%v stderr=%s, want a TTY", done, rc.cfg.TTY, stderr)
	}
	rc, _, done, stderr = parse(t, "-ti", "-image=x")
	if done || !rc.cfg.TTY {
		t.Fatalf("-ti: done=%v TTY=%v stderr=%s, want a TTY", done, rc.cfg.TTY, stderr)
	}
	rc, _, done, stderr = parse(t, "-i", "-image=x")
	if done || rc.cfg.TTY {
		t.Fatalf("-i alone: done=%v TTY=%v stderr=%s, want no TTY", done, rc.cfg.TTY, stderr)
	}
}

func TestExpandShortClustersLeavesTheGuestArgumentsAlone(t *testing.T) {
	got := expandShortClusters([]string{"-itP", "-ro", "-p", "80", "alpine", "-it", "ls"})
	want := []string{"-i", "-t", "-P", "-ro", "-p", "80", "alpine", "-it", "ls"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("expandShortClusters = %q, want %q: -ro is a flag name, and the arguments after the image belong to the guest", got, want)
	}
	got = expandShortClusters([]string{"-image=x", "--", "-it"})
	if want = []string{"-image=x", "--", "-it"}; !reflect.DeepEqual(got, want) {
		t.Errorf("expandShortClusters = %q, want %q", got, want)
	}
}

func TestRunFlagsDockerPlatform(t *testing.T) {
	rc, _, done, stderr := parse(t, "--platform", "linux/arm64", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	if rc.cfg.Architecture != "arm64" || rc.cfg.Platform != gvx.PlatformAuto || !rc.autoPlatform {
		t.Errorf("Architecture %q Platform %q autoPlatform %v, want arm64 on the automatic backend", rc.cfg.Architecture, rc.cfg.Platform, rc.autoPlatform)
	}
	rc, _, done, stderr = parse(t, "--platform=systrap", "-image=x")
	if done || rc.cfg.Platform != gvx.PlatformSystrap || rc.autoPlatform {
		t.Errorf("--platform=systrap: done=%v Platform=%q autoPlatform=%v stderr=%s", done, rc.cfg.Platform, rc.autoPlatform, stderr)
	}
}

func TestRunFlagsRejectUnsupportedAndInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"detach", []string{"-d", "-image=x"}, "-d is not supported"},
		{"windows image platform", []string{"--platform", "windows/amd64", "-image=x"}, "image platform"},
		{"host network", []string{"--network", "host", "-image=x"}, "network"},
		{"small memory", []string{"-m", "1m", "-image=x"}, "-m"},
		{"bad cpus", []string{"--cpus", "abc", "-image=x"}, "--cpus"},
		{"bad env name", []string{"-e", "A B=1", "-image=x"}, "-e"},
		{"missing env file", []string{"--env-file", filepath.Join(t.TempDir(), "absent.env"), "-image=x"}, "--env-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code, done, stderr := parse(t, tc.args...)
			if !done || code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("parseRunArgs(%v) = (code %d, done %v, stderr %q), want usage error 2 that mentions %q", tc.args, code, done, stderr, tc.want)
			}
		})
	}
}
