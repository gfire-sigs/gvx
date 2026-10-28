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
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

func parse(t *testing.T, args ...string) (runConfig, int, bool, string) {
	t.Helper()
	var stderr bytes.Buffer
	rc, code, done := parseRunArgs(args, nil, &bytes.Buffer{}, &stderr)
	return rc, code, done, stderr.String()
}

func TestParseRunArgsDefaults(t *testing.T) {
	rc, _, done, stderr := parse(t, "-image=alpine:3.20", "--", "echo", "hi")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	cfg := rc.cfg
	if cfg.DisableHostLockdown {
		t.Errorf("DisableHostLockdown = true by default, want the lockdown on")
	}
	if cfg.Platform != gvx.PlatformAuto || !rc.autoPlatform {
		t.Errorf("Platform = %q autoPlatform = %v, want auto", cfg.Platform, rc.autoPlatform)
	}
	if cfg.Architecture != runtime.GOARCH {
		t.Errorf("Architecture = %q, want %q", cfg.Architecture, runtime.GOARCH)
	}
	if cfg.NetworkMode != gvx.NetModeNAT {
		t.Errorf("NetworkMode = %q, want nat", cfg.NetworkMode)
	}
	if cfg.OCIImage != "alpine:3.20" || strings.Join(cfg.Cmd, " ") != "echo hi" || len(cfg.Argv) != 0 {
		t.Errorf("image/cmd/argv = %q %q %q, want the arguments of an image as Cmd and no Argv", cfg.OCIImage, cfg.Cmd, cfg.Argv)
	}
}

func TestParseRunArgsLockdownOptOut(t *testing.T) {
	for _, tc := range []struct {
		flag        string
		wantDisable bool
	}{
		{"-lockdown=false", true},
		{"-lockdown=true", false},
		{"-lockdown", false},
	} {
		rc, _, done, stderr := parse(t, tc.flag, "-image=x")
		if done {
			t.Fatalf("%s ended the command: %s", tc.flag, stderr)
		}
		if rc.cfg.DisableHostLockdown != tc.wantDisable {
			t.Errorf("%s: DisableHostLockdown = %v, want %v", tc.flag, rc.cfg.DisableHostLockdown, tc.wantDisable)
		}
	}
}

func TestParseRunArgsExplicitSettings(t *testing.T) {
	rc, _, done, stderr := parse(t,
		"-platform=HVF", "-arch=ARM64", "-net=None", "-workspace=/w", "-ro",
		"-cache-dir=/c", "-registry-url=http://r", "-wg-config=wg.conf", "-isolate-lan", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	cfg := rc.cfg
	if cfg.Platform != gvx.PlatformHVF || rc.autoPlatform {
		t.Errorf("Platform = %q autoPlatform = %v, want hvf and false", cfg.Platform, rc.autoPlatform)
	}
	if cfg.Architecture != "arm64" || cfg.NetworkMode != gvx.NetModeNone {
		t.Errorf("Architecture = %q NetworkMode = %q, want arm64 and none", cfg.Architecture, cfg.NetworkMode)
	}
	if cfg.WorkspacePath != "/w" || !cfg.WorkspaceReadOnly || cfg.OCICacheDir != "/c" ||
		cfg.RegistryBaseURL != "http://r" || cfg.WireGuardConfigPath != "wg.conf" || !cfg.IsolateLAN {
		t.Errorf("config = %+v", cfg)
	}
}

func TestParseRunArgsPortForwards(t *testing.T) {
	rc, _, done, stderr := parse(t, "-p", "8080:80,9090:90/udp", "-p", "7000:70", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	if got := len(rc.cfg.PortForwards); got != 3 {
		t.Fatalf("PortForwards = %d entries, want 3", got)
	}
	if pf := rc.cfg.PortForwards[1]; pf.HostPort != 9090 || pf.GuestPort != 90 || pf.Protocol != "udp" {
		t.Errorf("PortForwards[1] = %+v", pf)
	}
}

func TestParseRunArgsUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"no target", nil, 2, "specify"},
		{"bad port", []string{"-p", "nope", "-image=x"}, 2, "nope"},
		{"unknown flag", []string{"-bogus"}, 2, "bogus"},
		{"help", []string{"--help"}, 0, "Usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code, done, stderr := parse(t, tc.args...)
			if !done || code != tc.wantCode || !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("parseRunArgs(%v) = (code %d, done %v, stderr %q), want (code %d, done, stderr containing %q)", tc.args, code, done, stderr, tc.wantCode, tc.wantStderr)
			}
		})
	}
}

func TestExecuteCLIDispatch(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no arguments", nil, 2, "", "Usage"},
		{"help", []string{"help"}, 0, "Usage", ""},
		{"unknown subcommand", []string{"bogus"}, 2, "", "unknown subcommand"},
		{"pull without target", []string{"pull"}, 2, "", "missing <image-or-archive>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := executeCLI(ctx, tc.args, nil, &stdout, &stderr)
			if code != tc.wantCode || !strings.Contains(stdout.String(), tc.wantStdout) || !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("executeCLI(%v) = (code %d, stdout %q, stderr %q), want (code %d, stdout containing %q, stderr containing %q)",
					tc.args, code, stdout.String(), stderr.String(), tc.wantCode, tc.wantStdout, tc.wantStderr)
			}
		})
	}
}
