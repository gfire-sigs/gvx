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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// overlayUpperSteps lists the guest steps of the parityprobe overlay modes.
// Every step must print PASS.
var overlayUpperSteps = []string{
	"raw-whiteout-mknod", "raw-opaque-xattr", "overlay-refuses-proc-upper", "overlay-mount",
	"overlay-initial-view", "overlay-delete-lower-file", "overlay-recreate-deleted",
	"overlay-rename-over-deleted", "overlay-rename-lower-file",
	"overlay-opaque-directory", "overlay-copy-up-write", "overlay-hardlink-copy-up",
	"overlay-awkward-names", "overlay-final-view", "overlay-umount", "overlay-exec-from-layers",
}

// overlayVerifySteps lists the steps that run after a new mount.
var overlayVerifySteps = []string{
	"raw-whiteout-reread", "raw-opaque-reread", "overlay-remount",
	"overlay-remount-view", "overlay-remount-umount",
}

// overlayUpperLayout describes one filesystem that holds the upper layer. The
// guest sees it at /data.
type overlayUpperLayout struct {
	name string
	// persistent is false for tmpfs, which loses its content at exit.
	persistent bool
	// mount returns the mount of one sandbox. All calls of one test return
	// the same host backing store.
	mount func(t *testing.T) func() gvx.Mount
}

func overlayUpperLayouts() []overlayUpperLayout {
	return []overlayUpperLayout{
		{name: "tmpfs", mount: func(*testing.T) func() gvx.Mount {
			return func() gvx.Mount { return gvx.Mount{Kind: gvx.MountTmpfs, GuestPath: "/data"} }
		}},
		{name: "ext4lite-named", persistent: true, mount: func(*testing.T) func() gvx.Mount {
			return func() gvx.Mount {
				return gvx.Mount{Kind: gvx.MountVolume, VolumeName: "ovlupper", GuestPath: "/data"}
			}
		}},
		{name: "ext4lite-image", persistent: true, mount: func(t *testing.T) func() gvx.Mount {
			image := filepath.Join(t.TempDir(), "upper.ext4")
			return func() gvx.Mount {
				return gvx.Mount{Kind: gvx.MountVolume, ImagePath: image, GuestPath: "/data"}
			}
		}},
		{name: "hostfs-bind", persistent: true, mount: func(t *testing.T) func() gvx.Mount {
			dir := t.TempDir()
			return func() gvx.Mount { return gvx.Mount{Kind: gvx.MountBind, HostPath: dir, GuestPath: "/data"} }
		}},
		{name: "hostfs-volume", persistent: true, mount: func(*testing.T) func() gvx.Mount {
			return func() gvx.Mount {
				return gvx.Mount{Kind: gvx.MountVolume, VolumeName: "ovlupperhost", Driver: gvx.DriverHostfs, GuestPath: "/data"}
			}
		}},
	}
}

// runOverlayProbe runs the probe with one mount at /data in the default
// lockdown-free SDK mode and returns the exit code and the output.
func runOverlayProbe(t *testing.T, b gateBackend, bin, cacheDir string, mount gvx.Mount, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var out, errOut bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            b.plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         cacheDir,
		BinaryPath:          bin,
		Argv:                append([]string{"/bin/app"}, args...),
		Mounts:              []gvx.Mount{mount},
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

// requireProbeSteps fails the test unless every step printed PASS and no
// step printed FAIL.
func requireProbeSteps(t *testing.T, what string, code int, out string, steps ...[]string) {
	t.Helper()
	if code != 0 || strings.Contains(out, "FAIL ") {
		t.Errorf("%s: exit code %d\n%s", what, code, out)
	}
	for _, list := range steps {
		for _, name := range list {
			if !strings.Contains(out, "PASS "+name+"\n") {
				t.Errorf("%s: step %s did not pass", what, name)
			}
		}
	}
}

// TestE2EOverlayUpperLayers mounts a guest overlay whose upper layer lives on
// tmpfs, an ext4lite volume, or a hostfs directory. The guest writes
// whiteouts, opaque directories, copied-up files, and a hard link. The same
// run then mounts the overlay again and verifies the view.
func TestE2EOverlayUpperLayers(t *testing.T) {
	bin := acceptprog.BuildParityProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		for _, layout := range overlayUpperLayouts() {
			t.Run(b.name+"/"+layout.name, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				mount := layout.mount(t)
				code, out := runOverlayProbe(t, b, bin, t.TempDir(), mount(), "overlay-upper", "/data")
				requireProbeSteps(t, "overlay-upper", code, out, overlayUpperSteps, overlayVerifySteps)
			})
		}
	}
}

// TestE2EOverlayUpperPersistsAcrossSandboxes writes whiteouts and opaque
// directories in one sandbox. A second sandbox on the same backing store
// still sees them, and a new overlay mount shows the same merged view.
func TestE2EOverlayUpperPersistsAcrossSandboxes(t *testing.T) {
	bin := acceptprog.BuildParityProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		for _, layout := range overlayUpperLayouts() {
			if !layout.persistent {
				continue
			}
			t.Run(b.name+"/"+layout.name, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				mount := layout.mount(t)
				cacheDir := t.TempDir()
				code, out := runOverlayProbe(t, b, bin, cacheDir, mount(), "overlay-write", "/data")
				requireProbeSteps(t, "overlay-write", code, out, overlayUpperSteps)
				code, out = runOverlayProbe(t, b, bin, cacheDir, mount(), "overlay-verify", "/data")
				requireProbeSteps(t, "overlay-verify", code, out, overlayVerifySteps)
			})
		}
	}
}

// TestE2EOverlayUpperSurvivesSigkill kills a child rungv after the guest
// synced its overlay writes. A new sandbox on the same backing store then
// sees the whiteouts, the opaque directories, and the copied-up files.
func TestE2EOverlayUpperSurvivesSigkill(t *testing.T) {
	bin := acceptprog.BuildParityProbe(t, runtime.GOARCH)
	rungv := toolPath(t, rungvPkg)
	layouts := []struct {
		name string
		bind bool
		// src returns the host directory of a bind mount or the image path
		// of a volume.
		src func(t *testing.T) string
	}{
		{name: "ext4lite-image", src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "kill.ext4") }},
		{name: "hostfs-bind", bind: true, src: func(t *testing.T) string { return t.TempDir() }},
	}
	for _, b := range fixedAddressBackends() {
		for _, layout := range layouts {
			t.Run(b.name+"/"+layout.name, func(t *testing.T) {
				requireFixedAddressBackend(t, b)
				src := layout.src(t)
				kind, mount := "volume", gvx.Mount{Kind: gvx.MountVolume, ImagePath: src, GuestPath: "/data"}
				if layout.bind {
					kind, mount = "bind", gvx.Mount{Kind: gvx.MountBind, HostPath: src, GuestPath: "/data"}
				}
				cacheDir := t.TempDir()

				args := []string{"run", "-platform=" + string(b.plat), "-net=none",
					"-cache-dir=" + cacheDir, "-bin=" + bin,
					"-mount=type=" + kind + ",src=" + src + ",dst=/data",
					"--", "overlay-write", "/data", "hold"}
				cmd := exec.Command(rungv, args...)
				stdout, stderr := newOutputLog(), newOutputLog()
				cmd.Stdout, cmd.Stderr = stdout, stderr
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("rungv stderr:\n%s", stderr.String())
					}
				})
				if err := cmd.Start(); err != nil {
					t.Fatalf("start rungv: %v", err)
				}
				exited := make(chan struct{})
				var waitErr error
				go func() {
					waitErr = cmd.Wait()
					close(exited)
				}()
				t.Cleanup(func() {
					_ = cmd.Process.Kill()
					<-exited
				})
				select {
				case <-exited:
					if strings.Contains(stderr.String(), "not position-independent") {
						t.Skipf("this engine cannot hold an executable that links at a fixed address: %s", stderr.String())
					}
				default:
				}
				stdout.waitFor(t, 0, "SYNCED\n", 3*time.Minute, exited)
				if err := cmd.Process.Kill(); err != nil {
					t.Fatalf("SIGKILL rungv: %v", err)
				}
				<-exited
				var exitErr *exec.ExitError
				if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() == 0 {
					t.Fatalf("rungv wait after kill = %v, want a non-zero exit", waitErr)
				}
				requireProbeSteps(t, "overlay-write before the kill", 0, stdout.String(), overlayUpperSteps)

				if _, err := os.Stat(src); err != nil {
					t.Fatalf("the backing store is missing after the kill: %v", err)
				}
				code, out := runOverlayProbe(t, b, bin, cacheDir, mount, "overlay-verify", "/data")
				requireProbeSteps(t, "overlay-verify after SIGKILL", code, out, overlayVerifySteps)
			})
		}
	}
}
