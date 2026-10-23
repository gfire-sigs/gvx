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
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"

	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
)

// otherArch returns the Linux architecture that differs from the host.
func otherArch() string {
	if runtime.GOARCH == "arm64" {
		return "amd64"
	}
	return "arm64"
}

func TestParsePortForward(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want PortForward
	}{
		{"8080:80", PortForward{HostPort: 8080, GuestPort: 80, Protocol: "tcp", BindAddress: "127.0.0.1"}},
		{"0:5353/udp", PortForward{HostPort: 0, GuestPort: 5353, Protocol: "udp", BindAddress: "127.0.0.1"}},
		{" 9000:9001/TCP ", PortForward{HostPort: 9000, GuestPort: 9001, Protocol: "tcp", BindAddress: "127.0.0.1"}},
	} {
		got, err := ParsePortForward(tc.spec)
		if err != nil {
			t.Fatalf("ParsePortForward(%q) failed: %v", tc.spec, err)
		}
		if got != tc.want {
			t.Fatalf("ParsePortForward(%q) = %+v, want %+v", tc.spec, got, tc.want)
		}
	}

	for _, spec := range []string{"", "1:2:3", "70000:80", "80:0", "80:80/sctp", "x:80"} {
		if _, err := ParsePortForward(spec); err == nil {
			t.Fatalf("ParsePortForward(%q) succeeded, want error", spec)
		}
	}
}

func TestConfigNormalizeDefaults(t *testing.T) {
	cfg := Config{WorkspacePath: "/some/dir"}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize() failed: %v", err)
	}
	if cfg.Platform != PlatformAuto || cfg.NetworkMode != NetModeNAT || cfg.Architecture != runtime.GOARCH {
		t.Fatalf("defaults = (%q, %q, %q), want (auto, nat, %s)", cfg.Platform, cfg.NetworkMode, cfg.Architecture, runtime.GOARCH)
	}
	if cfg.WorkDir != "/workspace" {
		t.Fatalf("WorkDir = %q, want /workspace when WorkspacePath is set", cfg.WorkDir)
	}
	if cfg.DisableHostLockdown {
		t.Fatalf("DisableHostLockdown defaults to true, want false (lockdown on)")
	}
}

func TestConfigNormalizeRejectsInvalid(t *testing.T) {
	pf := []PortForward{{HostPort: 8080, GuestPort: 80, Protocol: "tcp"}}
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"unknown platform", Config{Platform: "kvm"}},
		{"unknown network mode", Config{NetworkMode: "bridge"}},
		{"unknown architecture", Config{Architecture: "riscv64"}},
		{"foreign architecture on hardware backend", Config{Platform: PlatformAuto, Architecture: otherArch()}},
		{"port forward with none", Config{NetworkMode: NetModeNone, PortForwards: pf}},
		{"port forward with wireguard", Config{NetworkMode: NetModeWireGuard, WireGuardConfigPath: "wg.conf", PortForwards: pf}},
		{"wireguard without config", Config{NetworkMode: NetModeWireGuard}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalize() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	// Only the host architecture runs on Linux, where the systrap platform is
	// the upstream one. The other hosts accept a foreign architecture for systrap.
	cfg := Config{Platform: PlatformSystrap, Architecture: otherArch()}
	err := cfg.normalize()
	if runtime.GOOS == "linux" {
		if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "only the host architecture") {
			t.Fatalf("normalize(systrap, %s) on Linux = %v, want ErrInvalidConfig that names the host architecture", otherArch(), err)
		}
	} else if err != nil {
		t.Fatalf("normalize(systrap, %s) failed: %v", otherArch(), err)
	}
}

func TestNewReportsSystrapPrerequisiteError(t *testing.T) {
	systraptest.RequireUnavailable(t)
	_, err := New(context.Background(), Config{
		Platform:            PlatformSystrap,
		NetworkMode:         NetModeNone,
		OCICacheDir:         t.TempDir(),
		DisableHostLockdown: true,
	})
	if err == nil {
		t.Fatalf("New(systrap) succeeded although the engine is unavailable")
	}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if !strings.Contains(err.Error(), "pagesize_16k") {
			t.Fatalf("New(systrap) error = %v, want the page-size requirement", err)
		}
		return
	}
	if !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("New(systrap) error = %v, want ErrPlatformUnavailable", err)
	}
}

func TestOpenAuto(t *testing.T) {
	hwErr := errors.New("hypervisor entitlement missing")
	fbErr := errors.New("stub spawn failed")
	failHW := func() (platform.Platform, string, error) { return nil, "", hwErr }
	failFB := func() (platform.Platform, string, error) { return nil, "", fbErr }
	named := func(name string, calls *int) opener {
		return func() (platform.Platform, string, error) {
			*calls++
			return nil, name, nil
		}
	}

	t.Run("hardware wins", func(t *testing.T) {
		var hwCalls, fbCalls int
		_, name, err := openAuto(named("hvf", &hwCalls), named("systrap", &fbCalls))
		if err != nil || name != "hvf" || fbCalls != 0 {
			t.Fatalf("openAuto = (%q, %v) with %d fallback calls, want (hvf, nil) and none", name, err, fbCalls)
		}
	})
	t.Run("fallback after hardware failure", func(t *testing.T) {
		var fbCalls int
		_, name, err := openAuto(failHW, named("systrap", &fbCalls))
		if err != nil || name != "systrap" || fbCalls != 1 {
			t.Fatalf("openAuto = (%q, %v) with %d fallback calls, want (systrap, nil) and one", name, err, fbCalls)
		}
	})
	t.Run("both failures are reported", func(t *testing.T) {
		_, _, err := openAuto(failHW, failFB)
		if !errors.Is(err, hwErr) || !errors.Is(err, fbErr) {
			t.Fatalf("openAuto error = %v, want it to wrap both backend errors", err)
		}
	})
}

func TestNewRejectsInvalidConfigBeforeOpeningHandles(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "never-created")
	_, err := New(context.Background(), Config{
		NetworkMode:  NetModeNone,
		PortForwards: []PortForward{{HostPort: 8080, GuestPort: 80, Protocol: "tcp"}},
		OCICacheDir:  cacheDir,
	})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("New(-p with none) error = %v, want ErrInvalidConfig", err)
	}
	if _, statErr := os.Stat(cacheDir); !os.IsNotExist(statErr) {
		t.Fatalf("New created cache dir before rejecting the config: stat error = %v", statErr)
	}
}

func TestLockdownOptionsByNetworkMode(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode         NetworkMode
		peerPort     uint16
		wantOutbound bool
		wantUDPPorts []uint16
	}{
		{"nat", NetModeNAT, 0, true, nil},
		{"none", NetModeNone, 0, false, nil},
		{"wireguard pins the peer port", NetModeWireGuard, 51820, false, []uint16{51820}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := &Sandbox{
				cfg: Config{NetworkMode: tc.mode},
				mounts: []sandboxMount{
					{Mount: Mount{Kind: MountBind, GuestPath: "/workspace", ReadOnly: true}, hostPath: "/ws"},
					{Mount: Mount{Kind: MountTmpfs, GuestPath: "/scratch"}},
					{Mount: Mount{Kind: MountVolume, GuestPath: "/vol"}, hostPath: "/vols/data"},
				},
				wgPeerPort: tc.peerPort,
			}
			opts := sb.lockdownOptions()
			wantMounts := []hostlockdown.HostMount{{Path: "/ws", ReadOnly: true}, {Path: "/vols/data"}}
			if opts.AllowOutboundNet != tc.wantOutbound || !slices.Equal(opts.Mounts, wantMounts) || !slices.Equal(opts.OutboundUDPPorts, tc.wantUDPPorts) {
				t.Fatalf("lockdownOptions() = %+v, want AllowOutboundNet=%v Mounts=%v OutboundUDPPorts=%v", opts, tc.wantOutbound, wantMounts, tc.wantUDPPorts)
			}
		})
	}
}

func TestWireGuardPeerPort(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		want     uint16
		wantErr  bool
	}{
		{"", 0, false},
		{"203.0.113.7:51820", 51820, false},
		{"vpn.example.com:443", 443, false},
		{"[2001:db8::1]:51820", 51820, false},
		{"no-port", 0, true},
		{"host:0", 0, true},
		{"host:http", 0, true},
		{"host:70000", 0, true},
	} {
		got, err := wireGuardPeerPort(tc.endpoint)
		if tc.wantErr {
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("wireGuardPeerPort(%q) error = %v, want ErrInvalidConfig", tc.endpoint, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("wireGuardPeerPort(%q) = (%d, %v), want (%d, nil)", tc.endpoint, got, err, tc.want)
		}
	}
}

func TestValidateELF64Arch(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		elfData, err := testelf.BuildGuestELF64(arch, 0, "x")
		if err != nil {
			t.Fatalf("BuildGuestELF64(%s) failed: %v", arch, err)
		}
		if err := validateELF64Arch(elfData, arch); err != nil {
			t.Fatalf("validateELF64Arch(%s ELF, %s) failed: %v", arch, arch, err)
		}
		other := "amd64"
		if arch == "amd64" {
			other = "arm64"
		}
		if err := validateELF64Arch(elfData, other); err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("validateELF64Arch(%s ELF, %s) error = %v, want mismatch", arch, other, err)
		}
	}
	if err := validateELF64Arch([]byte("not an elf"), runtime.GOARCH); err == nil {
		t.Fatalf("validateELF64Arch(garbage) succeeded, want parse error")
	}
	if err := validateELF64Arch(nil, "riscv64"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("validateELF64Arch(riscv64) error = %v, want ErrInvalidConfig", err)
	}
}

// failingWriter models a closed host pipe.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestStdioWriteReturnsEIOWhenHostWriteFails(t *testing.T) {
	ctx := gvcontext.Background()
	data := []byte("guest output")

	failing := &stdioFD{writer: failingWriter{err: io.ErrClosedPipe}, mu: new(sync.Mutex)}
	n, err := failing.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if !linuxerr.Equals(linuxerr.EIO, err) || n != 0 {
		t.Fatalf("Write to failing host writer = (%d, %v), want (0, EIO)", n, err)
	}

	var sink strings.Builder
	ok := &stdioFD{writer: &sink, mu: new(sync.Mutex)}
	n, err = ok.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil || n != int64(len(data)) || sink.String() != string(data) {
		t.Fatalf("Write to host writer = (%d, %v) sink=%q, want (%d, nil) %q", n, err, sink.String(), len(data), data)
	}
}

func TestResolveImageSelectsRequestedArchitecture(t *testing.T) {
	layerFor := func(arch string) []byte {
		layer, err := testimage.Tar(testimage.File{Name: "arch.txt", Data: []byte(arch + "\n")})
		if err != nil {
			t.Fatalf("testimage.Tar failed: %v", err)
		}
		return layer
	}
	baseURL := testimage.NewRegistry(t, "gvx/archtest", "v1",
		testimage.Image{Arch: "amd64", Layers: [][]byte{layerFor("amd64")}, Cmd: []string{"/amd64"}},
		testimage.Image{Arch: "arm64", Layers: [][]byte{layerFor("arm64")}, Cmd: []string{"/arm64"}},
	)

	digests := make(map[string]string)
	for _, arch := range []string{"amd64", "arm64"} {
		cache, err := NewLayerCache(t.TempDir())
		if err != nil {
			t.Fatalf("NewLayerCache failed: %v", err)
		}
		img, err := ResolveImage(context.Background(), cache, baseURL, "gvx/archtest:v1", arch)
		if err != nil {
			t.Fatalf("ResolveImage(%s) failed: %v", arch, err)
		}
		if len(img.LayerDigests) != 1 || len(img.Config.Cmd) != 1 || img.Config.Cmd[0] != "/"+arch {
			t.Fatalf("ResolveImage(%s) = digests %v cmd %v, want one layer and Cmd [/%s]", arch, img.LayerDigests, img.Config.Cmd, arch)
		}
		digests[arch] = img.LayerDigests[0]
		if err := img.Close(); err != nil {
			t.Fatalf("Close(%s) failed: %v", arch, err)
		}
	}
	if digests["amd64"] == digests["arm64"] {
		t.Fatalf("amd64 and arm64 resolved to the same layer digest %s", digests["amd64"])
	}

	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}
	if _, err := ResolveImage(context.Background(), cache, baseURL, "gvx/archtest:v1", "s390x"); err == nil {
		t.Fatalf("ResolveImage(s390x) succeeded, want missing manifest error")
	}
}

func TestResolveImageFallsBackToCacheWhenRegistryIsDown(t *testing.T) {
	layer, err := testimage.Tar(testimage.File{Name: "marker", Data: []byte("cached\n")})
	if err != nil {
		t.Fatalf("testimage.Tar failed: %v", err)
	}
	registry := testimage.NewRegistryServer(t, "gvx/offline", "v1",
		testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{layer}, Cmd: []string{"/marker"}})
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}

	online, err := ResolveImage(context.Background(), cache, registry.URL, "gvx/offline:v1", runtime.GOARCH)
	if err != nil {
		t.Fatalf("online ResolveImage failed: %v", err)
	}
	digests := slices.Clone(online.LayerDigests)
	if err := online.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	registry.Close()
	offline, err := ResolveImage(context.Background(), cache, registry.URL, "gvx/offline:v1", runtime.GOARCH)
	if err != nil {
		t.Fatalf("offline ResolveImage with a cached image failed: %v", err)
	}
	defer func() {
		if err := offline.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	}()
	if !slices.Equal(offline.LayerDigests, digests) || len(offline.Config.Cmd) != 1 || offline.Config.Cmd[0] != "/marker" {
		t.Fatalf("offline image = digests %v cmd %v, want digests %v and Cmd [/marker]", offline.LayerDigests, offline.Config.Cmd, digests)
	}

	emptyCache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}
	if _, err := ResolveImage(context.Background(), emptyCache, registry.URL, "gvx/offline:v1", runtime.GOARCH); err == nil {
		t.Fatalf("offline ResolveImage with an empty cache succeeded, want the network error")
	}
}
