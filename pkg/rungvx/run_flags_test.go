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
		{"negative bandwidth", []string{"--net-tx-bps=-1", "-image=x"}, "net-tx-bps:"},
		{"non-NAT bandwidth", []string{"--net=none", "--net-rx-bps=0", "-image=x"}, "require -net=nat"},
		{"bad env name", []string{"-e", "A B=1", "-image=x"}, "-e"},
		{"unknown pull policy", []string{"--pull", "sometimes", "-image=x"}, "--pull"},
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

func TestRunFlagsPullPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want gvx.PullPolicy
	}{
		{"default", []string{"-image=x"}, gvx.PullMissing},
		{"always", []string{"--pull=always", "-image=x"}, gvx.PullAlways},
		{"missing", []string{"--pull", "missing", "-image=x"}, gvx.PullMissing},
		{"never with one dash", []string{"-pull=never", "-image=x"}, gvx.PullNever},
		{"case and spaces", []string{"--pull", " Never ", "-image=x"}, gvx.PullNever},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, done, stderr := parse(t, tc.args...)
			if done {
				t.Fatalf("parseRunArgs ended the command: %s", stderr)
			}
			if rc.cfg.PullPolicy != tc.want {
				t.Errorf("PullPolicy = %q, want %q", rc.cfg.PullPolicy, tc.want)
			}
		})
	}
}

func TestRunFlagsHostCACertsIsOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"default", []string{"-image=x"}, false},
		{"single dash", []string{"-host-ca-certs", "-image=x"}, true},
		{"double dash", []string{"--host-ca-certs", "-image=x"}, true},
		{"explicit false", []string{"--host-ca-certs=false", "-image=x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, done, stderr := parse(t, tc.args...)
			if done {
				t.Fatalf("parseRunArgs ended the command: %s", stderr)
			}
			if rc.cfg.HostCACerts != tc.want {
				t.Errorf("HostCACerts = %v, want %v", rc.cfg.HostCACerts, tc.want)
			}
		})
	}
}

func TestRunFlagsAllowUnconfinedSystrapIsOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"default", []string{"-image=x"}, false},
		{"single dash", []string{"-allow-unconfined-systrap", "-image=x"}, true},
		{"double dash", []string{"--allow-unconfined-systrap", "-image=x"}, true},
		{"explicit false", []string{"--allow-unconfined-systrap=false", "-image=x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, done, stderr := parse(t, tc.args...)
			if done {
				t.Fatalf("parseRunArgs ended the command: %s", stderr)
			}
			if rc.cfg.AllowUnconfinedSystrap != tc.want {
				t.Errorf("AllowUnconfinedSystrap = %v, want %v", rc.cfg.AllowUnconfinedSystrap, tc.want)
			}
		})
	}
}

func TestRunFlagsOverlayMount(t *testing.T) {
	rc, _, done, stderr := parse(t,
		"--mount", "type=overlay,src=base-vol,upper=branch-a,dst=/mnt/persist",
		"--mount", "type=overlay,src=base-vol,dst=/mnt/scratch,tmpfs-size=16m",
		"-image=x",
	)
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	want := []gvx.Mount{
		{Kind: gvx.MountOverlay, VolumeName: "base-vol", UpperVolumeName: "branch-a", GuestPath: "/mnt/persist"},
		{Kind: gvx.MountOverlay, VolumeName: "base-vol", GuestPath: "/mnt/scratch", TmpfsSizeBytes: 16 << 20},
	}
	if !reflect.DeepEqual(rc.cfg.Mounts, want) {
		t.Fatalf("Mounts = %+v, want %+v", rc.cfg.Mounts, want)
	}

	_, code, badDone, badStderr := parse(t, "--mount", "type=overlay,src=same,upper=same,dst=/mnt/bad", "-image=x")
	if !badDone || code != 2 || !strings.Contains(badStderr, "--mount") {
		t.Fatalf("self-overlay = (code=%d, done=%v, stderr=%q), want usage error 2", code, badDone, badStderr)
	}
}

func TestRunFlagsAutoPublishIsOptIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"default", []string{"-image=x"}, false},
		{"single dash", []string{"-auto-publish", "-image=x"}, true},
		{"double dash", []string{"--auto-publish", "-image=x"}, true},
		{"explicit false", []string{"--auto-publish=false", "-image=x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, done, stderr := parse(t, tc.args...)
			if done {
				t.Fatalf("parseRunArgs ended the command: %s", stderr)
			}
			if rc.cfg.AutoPublishPorts != tc.want {
				t.Errorf("AutoPublishPorts = %v, want %v", rc.cfg.AutoPublishPorts, tc.want)
			}
		})
	}
}

func TestRunFlagsSetNATBandwidth(t *testing.T) {
	rc, code, done, stderr := parse(t, "--network=bridge", "--net-tx-bps", "1000000000000", "--net-rx-bps=100", "-image=x")
	if done || code != 0 {
		t.Fatalf("parse NAT bandwidth flags: code=%d, done=%t, stderr=%q", code, done, stderr)
	}
	rates := rc.cfg.NetworkBandwidth
	if rates.TXBPS != 1_000_000_000_000 || rates.RXBPS != 100 {
		t.Fatalf("configured bandwidth = %+v, want TX 1000000000000 and RX 100 bps", rates)
	}
	if _, code, done, _ := parse(t, "--net-tx-bps=1000000000001", "-image=x"); !done || code != 2 {
		t.Fatalf("parse rate above NAT bandwidth maximum: code=%d, done=%t, want usage error", code, done)
	}
}

func TestRunFlagsMountVolumeSizeAndEphemeral(t *testing.T) {
	rc, _, done, stderr := parse(t,
		"--mount", "type=volume,src=data,dst=/data,size=64m",
		"--mount", "type=volume,dst=/scratch,ephemeral,size=32m",
		"-image=x",
	)
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	want := []gvx.Mount{
		{Kind: gvx.MountVolume, VolumeName: "data", GuestPath: "/data", SizeBytes: 64 << 20},
		{Kind: gvx.MountVolume, GuestPath: "/scratch", Ephemeral: true, SizeBytes: 32 << 20},
	}
	if !reflect.DeepEqual(rc.cfg.Mounts, want) {
		t.Fatalf("Mounts = %+v, want %+v", rc.cfg.Mounts, want)
	}

	for _, bad := range []string{
		"type=volume,src=data,dst=/data,size=20m",
		"type=volume,src=data,dst=/scratch,ephemeral",
		"type=volume,dst=/scratch,ephemeral,readonly",
	} {
		_, code, badDone, badStderr := parse(t, "--mount", bad, "-image=x")
		if !badDone || code != 2 || !strings.Contains(badStderr, "--mount") {
			t.Fatalf("--mount %q = (code=%d, done=%v, stderr=%q), want usage error 2", bad, code, badDone, badStderr)
		}
	}
}
