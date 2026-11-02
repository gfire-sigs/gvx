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

//go:build darwin || windows || linux

package e2e

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// runParityProbe runs the parityprobe guest with args and returns the exit
// code and the standard output. The guest has no image, so it needs no
// registry.
func runParityProbe(t *testing.T, b gateBackend, bin string, allowSUID bool, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var out, errOut bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            b.plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		BinaryPath:          bin,
		Argv:                append([]string{"/bin/app"}, args...),
		AllowSUID:           allowSUID,
		Stdout:              &out,
		Stderr:              &errOut,
		DisableHostLockdown: true,
	})
	skipWhenFixedAddressRefused(t, "New(parityprobe)", err)
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	code, err := sb.Run(ctx)
	skipWhenFixedAddressRefused(t, "Run(parityprobe)", err)
	if errOut.Len() > 0 {
		t.Logf("guest stderr:\n%s", errOut.String())
	}
	return code, out.String()
}

// TestE2ERunscParityKernelFeatures checks the guest kernel features that
// runsc gives a container and that systemd, runc, and dockerd use.
func TestE2ERunscParityKernelFeatures(t *testing.T) {
	bin := acceptprog.BuildParityProbe(t, runtime.GOARCH)
	want := []string{
		"tmpfs-percent-size", "cgroup2-mounted", "mqueue-mounted", "mq-open",
		"dev-fuse", "dev-net-tun", "uevent-socket", "loopback-named",
		"new-netns-has-lo", "pivot-root", "keyring-link", "overlay-dentry-cache", "mnt-ns-setns",
	}
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			code, out := runParityProbe(t, b, bin, false, "checks")
			if code != 0 || !strings.Contains(out, "DONE") {
				t.Fatalf("parityprobe checks exited with %d\n%s", code, out)
			}
			for _, name := range want {
				if !strings.Contains(out, "PASS "+name+"\n") {
					t.Errorf("check %s did not pass", name)
				}
			}
			if strings.Contains(out, "FAIL ") {
				t.Errorf("failed checks:\n%s", out)
			}
		})
	}
}

// TestE2ERebootStopsSandbox checks that reboot(2) in the guest ends the run
// while another guest process sleeps. A power off ends it with status 0, and a
// restart ends it as if SIGHUP killed init.
func TestE2ERebootStopsSandbox(t *testing.T) {
	bin := acceptprog.BuildParityProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			for _, tc := range []struct {
				mode     string
				wantCode int
			}{
				{mode: "poweroff", wantCode: 0},
				{mode: "restart", wantCode: 128 + 1},
			} {
				start := time.Now()
				code, out := runParityProbe(t, b, bin, false, tc.mode)
				if code != tc.wantCode || strings.Contains(out, "FAIL") {
					t.Errorf("%s: exit code %d, want %d\n%s", tc.mode, code, tc.wantCode, out)
				}
				if took := time.Since(start); took > 30*time.Second {
					t.Errorf("%s: the run took %v; the sleeping child kept it alive", tc.mode, took)
				}
			}
		})
	}
}

// TestE2EAllowSUID checks that the guest obeys the set-user-ID bit only when
// Config.AllowSUID is set, as runsc does with --allow-suid.
func TestE2EAllowSUID(t *testing.T) {
	bin := acceptprog.BuildParityProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			for _, tc := range []struct {
				allow bool
				want  string
			}{
				{allow: false, want: "uid=1000 euid=1000"},
				{allow: true, want: "uid=1000 euid=0"},
			} {
				code, out := runParityProbe(t, b, bin, tc.allow, "euid")
				if code != 0 || !strings.Contains(out, tc.want) {
					t.Errorf("AllowSUID=%t: exit code %d, output %q, want %q", tc.allow, code, out, tc.want)
				}
			}
		})
	}
}
