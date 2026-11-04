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
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2EWriteFaultInPrivateFileMapping makes a write fault the first access to a
// private mapping of a file on a bind mount and on a volume, at a chunk
// boundary of the file. These file systems translate each 64 KiB chunk of a
// file on its own. A translation can then end before the faulting page. The
// Sentry once stopped with "invalid allocation length: 0x0" in that case, and
// a k3s node on Windows arm64 lost its Sentry that way.
func TestE2EWriteFaultInPrivateFileMapping(t *testing.T) {
	bin := acceptprog.BuildCOWProbe(t, hostArch())
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			if (b.plat == gvx.PlatformHVF || b.plat == gvx.PlatformWHPX) && !hvtest.Available() {
				t.Skip("no hardware hypervisor on this host")
			}
			requireFixedAddressBackend(t, b)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			var out, errOut bytes.Buffer
			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         sharedCacheDir(t),
				BinaryPath:          bin,
				Argv:                []string{"/bin/cowprobe", "dir=/workspace", "dir=/mnt/vol"},
				WorkspacePath:       t.TempDir(),
				Mounts:              []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "cowvol", GuestPath: "/mnt/vol"}},
				Stdout:              &out,
				Stderr:              &errOut,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "New(cowprobe)", err)
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close(%s): %v", b.name, err)
				}
			}()
			code, err := sb.Run(ctx)
			skipWhenFixedAddressRefused(t, "Run(cowprobe)", err)
			t.Logf("guest output on %s:\n%s", b.name, out.String())
			for _, dir := range []string{"/workspace", "/mnt/vol"} {
				if !strings.Contains(out.String(), "PASS cow-prefix:"+dir+"\n") {
					t.Errorf("the write faults on %s did not pass on %s", dir, b.name)
				}
			}
			if err != nil || code != 0 || !strings.Contains(out.String(), "COWPROBE-OK") {
				t.Fatalf("cowprobe on %s = (%d, %v)\nstderr:\n%s", b.name, code, err, errOut.String())
			}
		})
	}
}
