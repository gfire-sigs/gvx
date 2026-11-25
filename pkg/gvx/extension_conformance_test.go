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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testimage"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/gvx/shm"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// TestExtensionHelperProcess acts as a real host worker subprocess when
// re-executed by conformance tests with GVX_EXT_TEST_HELPER=1.
func TestExtensionHelperProcess(t *testing.T) {
	if os.Getenv("GVX_EXT_TEST_HELPER") != "1" {
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, "ready")
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

// TestExtensionLockdownSecondSandboxHelper runs inside a child test process
// that applies real hostlockdown and verifies second-sandbox extension guards.
func TestExtensionLockdownSecondSandboxHelper(t *testing.T) {
	if os.Getenv("GVX_EXT_LOCKDOWN_HELPER") != "1" {
		return
	}
	if _, err := hostlockdown.Apply(hostlockdown.Options{
		AllowOutboundNet:     false,
		InstallSyscallFilter: func() error { return nil },
	}); err != nil {
		if errors.Is(err, hostlockdown.ErrUnsupported) {
			t.Skip("hostlockdown unsupported on this OS")
		}
		t.Fatalf("hostlockdown.Apply: %v", err)
	}
	recordProcessExtensionLockdown([]int{42})

	ctx := context.Background()
	spawningExt := &conformanceExtension{
		name:             "spawner",
		needsHelperSpawn: true,
		spawnRealHelper:  false,
	}
	if _, err := New(ctx, Config{
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		NetworkMode:            NetModeNone,
		DisableHostLockdown:    true,
		Extensions:             []Extension{spawningExt},
	}); !errors.Is(err, ErrLockdownActive) {
		t.Fatalf("New(spawning ext after lockdown) err = %v, want ErrLockdownActive", err)
	}

	ungrantedFDExt := &conformanceExtension{
		name:       "ungranted-fd",
		recvMsgFDs: []int{99},
	}
	if _, err := New(ctx, Config{
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		NetworkMode:            NetModeNone,
		DisableHostLockdown:    true,
		Extensions:             []Extension{ungrantedFDExt},
	}); !errors.Is(err, ErrLockdownActive) {
		t.Fatalf("New(ungranted RecvMsgFDs after lockdown) err = %v, want ErrLockdownActive", err)
	}

	// Non-spawning extension whose requested RecvMsgFD is already in the recorded
	// process lockdown grant must pass openExtensions cleanly.
	pureExt := &conformanceExtension{
		name:             "pure-in-process",
		needsHelperSpawn: false,
		recvMsgFDs:       []int{42},
	}
	sb := &Sandbox{
		cfg:      Config{Extensions: []Extension{pureExt}},
		platName: "hvf",
	}
	if err := sb.openExtensions(ctx); err != nil {
		t.Fatalf("openExtensions(non-spawning ext with satisfied grant) err = %v, want nil", err)
	}
	_ = sb.Close()
}

type conformanceExtension struct {
	name             string
	validateErr      error
	needsHelperSpawn bool
	spawnRealHelper  bool
	recvMsgFDs       []int
	ckptPolicy       CheckpointPolicy
	topos            []sys.TopologyAddition
	registerDevName  string
	devMajor         uint32
	devMinor         uint32
	closeErr         error

	mu             sync.Mutex
	boundInstances []*conformanceBound
	closeEvents    *[]string
}

func (e *conformanceExtension) Name() string { return e.name }

func (e *conformanceExtension) Validate(env ValidationEnv) error {
	if e.validateErr != nil {
		return e.validateErr
	}
	return nil
}

func (e *conformanceExtension) OpenPreLockdown(ctx context.Context, env PreLockdownEnv) (BoundExtension, error) {
	b := &conformanceBound{
		ext:       e,
		abortCh:   make(chan struct{}),
		blockedCh: make(chan struct{}),
	}
	if e.spawnRealHelper {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		hp, err := env.SpawnHelper(ctx, HelperSpec{
			Name: e.name + "-helper",
			Path: exe,
			Args: []string{"-test.run=^TestExtensionHelperProcess$"},
			Env:  append(os.Environ(), "GVX_EXT_TEST_HELPER=1"),
		})
		if err != nil {
			return nil, err
		}
		b.helper = hp
	}
	e.mu.Lock()
	e.boundInstances = append(e.boundInstances, b)
	e.mu.Unlock()
	return b, nil
}

type conformanceBound struct {
	ext       *conformanceExtension
	helper    *HelperProcess
	abortOnce sync.Once
	abortCh   chan struct{}
	aborted   atomic.Bool
	blockedCh chan struct{}
	blockOnce sync.Once

	mu           sync.Mutex
	attachedCnt  int
	closeCalls   []bool
	inspectCalls int
	statsCalls   int
}

func (b *conformanceBound) NeedsHelperSpawn() bool { return b.ext.needsHelperSpawn }

func (b *conformanceBound) LockdownRequirements() ExtensionLockdown {
	return ExtensionLockdown{RecvMsgFDs: slices.Clone(b.ext.recvMsgFDs)}
}

func (b *conformanceBound) CheckpointPolicy() CheckpointPolicy { return b.ext.ckptPolicy }

func (b *conformanceBound) SysfsTopologies() []sys.TopologyAddition { return b.ext.topos }

func (b *conformanceBound) AttachKernel(_ context.Context, kenv *KernelEnv) error {
	b.mu.Lock()
	b.attachedCnt++
	b.mu.Unlock()
	if b.ext.registerDevName != "" {
		major := b.ext.devMajor
		if major == 0 {
			major = 226
		}
		minor := b.ext.devMinor
		if minor == 0 {
			minor = 128
		}
		if err := kenv.VFS.RegisterDevice(vfs.CharDevice, major, minor, &conformanceCharDevice{bound: b}, &vfs.RegisterDeviceOptions{
			GroupName: "extconformance",
			Pathname:  b.ext.registerDevName,
			FilePerms: 0o666,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (b *conformanceBound) AbortPending() {
	b.aborted.Store(true)
	b.abortOnce.Do(func() { close(b.abortCh) })
}

func (b *conformanceBound) Close(guestUnmapped bool) error {
	b.mu.Lock()
	b.closeCalls = append(b.closeCalls, guestUnmapped)
	b.mu.Unlock()
	if b.ext.closeEvents != nil {
		b.ext.mu.Lock()
		*b.ext.closeEvents = append(*b.ext.closeEvents, fmt.Sprintf("%s:%t", b.ext.name, guestUnmapped))
		b.ext.mu.Unlock()
	}
	return b.ext.closeErr
}

func (b *conformanceBound) Inspect() (json.RawMessage, error) {
	b.mu.Lock()
	b.inspectCalls++
	attached := b.attachedCnt
	b.mu.Unlock()
	helperPID := 0
	if b.helper != nil {
		helperPID = b.helper.PID()
	}
	return json.Marshal(map[string]any{
		"attached":   attached,
		"helper_pid": helperPID,
		"aborted":    b.aborted.Load(),
	})
}

func (b *conformanceBound) Stats() (json.RawMessage, error) {
	b.mu.Lock()
	b.statsCalls++
	calls := b.statsCalls
	b.mu.Unlock()
	return json.Marshal(map[string]any{
		"samples": calls,
	})
}

type conformanceCharDevice struct {
	bound *conformanceBound
}

func (d *conformanceCharDevice) Open(ctx gvcontext.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &conformanceCharFD{bound: d.bound}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

type conformanceCharFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	bound *conformanceBound
}

func (*conformanceCharFD) Release(gvcontext.Context) {}

func (fd *conformanceCharFD) Read(ctx gvcontext.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	if fd.bound.aborted.Load() {
		return 0, linuxerr.ENODEV
	}
	fd.bound.blockOnce.Do(func() { close(fd.bound.blockedCh) })
	if err := ctx.Block(fd.bound.abortCh); err != nil {
		return 0, err
	}
	return 0, linuxerr.ENODEV
}

func (fd *conformanceCharFD) PRead(ctx gvcontext.Context, dst usermem.IOSequence, _ int64, opts vfs.ReadOptions) (int64, error) {
	return fd.Read(ctx, dst, opts)
}

func (*conformanceCharFD) ConfigureMMap(_ gvcontext.Context, _ *memmap.MMapOpts) error {
	return linuxerr.ENODEV
}

func TestExtensionValidationAndTopologyCollisionInNew(t *testing.T) {
	ctx := context.Background()

	// Duplicate extension names fail in New before opening host handles.
	e1 := &conformanceExtension{name: "dup"}
	e2 := &conformanceExtension{name: "dup"}
	if _, err := New(ctx, Config{
		DisableHostLockdown: true,
		NetworkMode:         NetModeNone,
		Extensions:          []Extension{e1, e2},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("duplicate extension err = %v, want ErrInvalidConfig", err)
	}

	// Restore rejects extensions cleanly.
	if _, err := Restore(ctx, Config{
		DisableHostLockdown: true,
		NetworkMode:         NetModeNone,
		Extensions:          []Extension{e1},
	}, RestoreOptions{Dir: t.TempDir()}); !errors.Is(err, ErrCheckpointExtensionUnsupported) {
		t.Fatalf("Restore with extension err = %v, want ErrCheckpointExtensionUnsupported", err)
	}

	// Conflicting sysfs topologies fail in New before boot.
	requireCheckpointGuestBackend(t)
	dupTopo := sys.TopologyAddition{
		Class: []sys.NodeSpec{
			{
				Name: "exttest",
				Kind: sys.NodeDir,
				Children: []sys.NodeSpec{
					{Name: "dup", Kind: sys.NodeFile, Content: "1\n"},
				},
			},
		},
	}
	if _, err := New(ctx, Config{
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		NetworkMode:            NetModeNone,
		DisableHostLockdown:    true,
		Extensions: []Extension{
			&conformanceExtension{name: "a", topos: []sys.TopologyAddition{dupTopo}},
			&conformanceExtension{name: "b", topos: []sys.TopologyAddition{dupTopo}},
		},
	}); !errors.Is(err, sys.ErrTopologyConflict) {
		t.Fatalf("New(conflicting sysfs topologies) err = %v, want sys.ErrTopologyConflict", err)
	}
}

func TestExtensionTeardownOutcomesAndClosingGuard(t *testing.T) {
	// Outcome 2: kernel stop timeout calls Close(false) in reverse order,
	// retains platform/memory, and keeps Sandbox open for a retryable Close().
	var events []string
	ext1 := &conformanceExtension{name: "first", closeEvents: &events}
	ext2 := &conformanceExtension{name: "second", closeEvents: &events}
	b1 := &conformanceBound{ext: ext1, abortCh: make(chan struct{}), blockedCh: make(chan struct{})}
	b2 := &conformanceBound{ext: ext2, abortCh: make(chan struct{}), blockedCh: make(chan struct{})}

	fakePlat := &fakeClosePlatform{}
	readyCh := make(chan struct{})
	close(readyCh)
	runDone := make(chan struct{})

	sb := &Sandbox{
		plat:           fakePlat,
		kernelReady:    readyCh,
		runDone:        runDone,
		runStarted:     true,
		shmImporter:    shm.NewImporter(shm.Options{HostMappingAlign: 4096, QuotaBytes: 65536}),
		boundExts:      []boundExtEntry{{name: "first", bound: b1}, {name: "second", bound: b2}},
		extStopTimeout: 30 * time.Millisecond,
	}

	err := sb.Close()
	if err == nil || !strings.Contains(err.Error(), "did not exit within") {
		t.Fatalf("first Close() err = %v, want timeout error", err)
	}
	wantFirst := []string{"second:false", "first:false"}
	if !slices.Equal(events, wantFirst) {
		t.Fatalf("Outcome 2 close order = %v, want %v", events, wantFirst)
	}
	if fakePlat.closeCalls.Load() != 0 {
		t.Fatalf("Platform.Close called %d times on timeout, want 0", fakePlat.closeCalls.Load())
	}

	// Release runDone and retry Close(): must now execute Outcome 1.
	close(runDone)
	if err := sb.Close(); err != nil {
		t.Fatalf("retry Close() err = %v, want nil", err)
	}
	wantRetry := []string{"second:false", "first:false", "second:true", "first:true"}
	if !slices.Equal(events, wantRetry) {
		t.Fatalf("retry close sequence = %v, want %v", events, wantRetry)
	}
	if fakePlat.closeCalls.Load() != 1 {
		t.Fatalf("Platform.Close called %d times after retry, want 1", fakePlat.closeCalls.Load())
	}

	// Closing guard rejects Run, Pause, and ServeControl once closed.
	if _, err := sb.Run(context.Background()); !errors.Is(err, ErrSandboxClosing) {
		t.Fatalf("Run after Close err = %v, want ErrSandboxClosing", err)
	}
	if err := sb.Pause(context.Background(), false); !errors.Is(err, ErrSandboxClosing) {
		t.Fatalf("Pause after Close err = %v, want ErrSandboxClosing", err)
	}
	if err := sb.ServeControl(context.Background()); !errors.Is(err, ErrSandboxClosing) {
		t.Fatalf("ServeControl after Close err = %v, want ErrSandboxClosing", err)
	}

	// Outcome 3: Platform.Close error calls Close(false) in reverse order and joins errors.
	events = nil
	platBoom := errors.New("fake platform close failure")
	extErr := errors.New("ext1 close warning")
	eA := &conformanceExtension{name: "alpha", closeEvents: &events, closeErr: extErr}
	eB := &conformanceExtension{name: "beta", closeEvents: &events}
	sb3 := &Sandbox{
		plat:      &fakeClosePlatform{err: platBoom},
		boundExts: []boundExtEntry{{name: "alpha", bound: &conformanceBound{ext: eA, abortCh: make(chan struct{}), blockedCh: make(chan struct{})}}, {name: "beta", bound: &conformanceBound{ext: eB, abortCh: make(chan struct{}), blockedCh: make(chan struct{})}}},
	}
	err3 := sb3.Close()
	if !errors.Is(err3, platBoom) || !errors.Is(err3, extErr) {
		t.Fatalf("Outcome 3 Close() err = %v, want joined platBoom and extErr", err3)
	}
	want3 := []string{"beta:false", "alpha:false"}
	if !slices.Equal(events, want3) {
		t.Fatalf("Outcome 3 close order = %v, want %v", events, want3)
	}
}

type fakeClosePlatform struct {
	platform.Platform
	closeCalls atomic.Int32
	err        error
}

func (p *fakeClosePlatform) Close() error {
	p.closeCalls.Add(1)
	return p.err
}

func buildExtensionGuestProbeELF(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling guest extension probe")
	}
	srcDir := t.TempDir()
	src := `package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	vendor, err := os.ReadFile("/sys/bus/pci/devices/0000:00:01.0/vendor")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read pci vendor: %v\n", err)
		os.Exit(2)
	}
	drmDev, err := os.ReadFile("/sys/class/drm/renderD128/dev")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read drm dev: %v\n", err)
		os.Exit(3)
	}
	fmt.Printf("VENDOR=%s DEV=%s\n", strings.TrimSpace(string(vendor)), strings.TrimSpace(string(drmDev)))
	f, err := os.Open("/dev/exttest0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "open /dev/exttest0: %v\n", err)
		os.Exit(4)
	}
	defer f.Close()
	buf := make([]byte, 16)
	_, _ = f.Read(buf)
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module extprobe\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "extprobe")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest extprobe: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read extprobe: %v", err)
	}
	return data
}

func TestExtensionConformanceGuestControlPausedCloseAndHelperReap(t *testing.T) {
	requireCheckpointGuestBackend(t)

	probeELF := buildExtensionGuestProbeELF(t)
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/extprobe", Data: probeELF, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	alloc := sys.NewSlotAllocator()
	pciSlot, err := alloc.AllocatePCISlot()
	if err != nil {
		t.Fatalf("AllocatePCISlot: %v", err)
	}
	virtioName := alloc.AllocateVirtioIndex()
	topo, err := sys.VirtioPCIDeviceTopology(sys.VirtioPCIDeviceSpec{
		PCISlot:    pciSlot,
		VirtioName: virtioName,
		VendorID:   0x1af4,
		DeviceID:   0x1050,
		ClassCode:  0x038000,
		ClassName:  "drm",
		NodeName:   "renderD128",
		Major:      226,
		Minor:      128,
	})
	if err != nil {
		t.Fatalf("VirtioPCIDeviceTopology: %v", err)
	}

	var closeOrder []string
	ext := &conformanceExtension{
		name:             "conformance",
		needsHelperSpawn: true,
		spawnRealHelper:  true,
		ckptPolicy:       CheckpointUnsupported,
		topos:            []sys.TopologyAddition{topo},
		registerDevName:  "exttest0",
		devMajor:         226,
		devMinor:         128,
		closeEvents:      &closeOrder,
	}

	sockPath := shortControlSocketPath(t, "ext.sock")
	ep, err := control.Listen(sockPath, control.ListenOptions{})
	if err != nil {
		t.Fatalf("control.Listen: %v", err)
	}
	t.Cleanup(ep.Cleanup)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sb, err := New(ctx, Config{
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		NetworkMode:            NetModeNone,
		OCILayerTars:           [][]byte{layer},
		OCICacheDir:            t.TempDir(),
		Argv:                   []string{"/bin/extprobe"},
		Stdout:                 &stdout,
		Stderr:                 &stderr,
		ControlListener:        ep.Listener,
		ControlToken:           ep.Token,
		DisableHostLockdown:    true,
		Extensions:             []Extension{ext},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctrlCtx, ctrlCancel := context.WithCancel(ctx)
	defer ctrlCancel()
	go func() { _ = sb.ServeControl(ctrlCtx) }()

	runDone := make(chan error, 1)
	go func() {
		_, rErr := sb.Run(ctx)
		runDone <- rErr
	}()

	bound := ext.boundInstances[0]
	if bound.helper == nil || bound.helper.PID() <= 0 {
		t.Fatalf("helper process not spawned: %+v", bound.helper)
	}

	// Wait until the guest reads sysfs and blocks inside /dev/exttest0 Read.
	select {
	case <-bound.blockedCh:
	case rErr := <-runDone:
		t.Fatalf("sandbox exited before blocking on /dev/exttest0: err=%v stdout=%q stderr=%q", rErr, stdout.String(), stderr.String())
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for guest to block on /dev/exttest0; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	// Connect over -S control socket: Inspect and Stats must work and carry extension snapshots.
	client, err := control.Dial(ctx, control.DialOptions{Endpoint: sockPath, Token: ep.Token})
	if err != nil {
		t.Fatalf("control.Dial: %v", err)
	}
	defer client.Close()

	var insp control.InspectResponse
	if err := client.Call(ctx, control.MethodInspect, nil, &insp); err != nil {
		t.Fatalf("client.Call(sandbox.inspect): %v", err)
	}
	rawExt, ok := insp.Extensions["conformance"]
	if !ok || !strings.Contains(string(rawExt), fmt.Sprintf(`"helper_pid":%d`, bound.helper.PID())) {
		t.Fatalf("Inspect.Extensions = %v, want conformance snapshot with helper_pid=%d", insp.Extensions, bound.helper.PID())
	}

	var stats control.StatsSample
	if err := client.Call(ctx, control.MethodStats, control.StatsRequest{}, &stats); err != nil {
		t.Fatalf("client.Call(sandbox.stats): %v", err)
	}
	if _, ok := stats.Extensions["conformance"]; !ok {
		t.Fatalf("Stats.Extensions = %v, want conformance entry", stats.Extensions)
	}

	// CheckpointStream over control socket must reject unsupported extensions.
	if err := sb.CheckpointStream(ctx, CheckpointOptions{LeaveRunning: true}, io.Discard); !errors.Is(err, ErrCheckpointExtensionUnsupported) {
		t.Fatalf("CheckpointStream err = %v, want ErrCheckpointExtensionUnsupported", err)
	}

	// Pause the sandbox before calling Close(): Close must unpause, abort pending,
	// kill guest, stop platform, call Close(true), and reap the helper process.
	if err := sb.Pause(ctx, false); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close on paused extension sandbox: %v", err)
	}
	<-runDone

	if !slices.Equal(closeOrder, []string{"conformance:true"}) {
		t.Fatalf("closeOrder = %v, want [conformance:true]", closeOrder)
	}
	select {
	case <-bound.helper.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("helper subprocess was not reaped after Sandbox.Close")
	}
	if !strings.Contains(stdout.String(), "VENDOR=0x1af4") || !strings.Contains(stdout.String(), "DEV=226:128") {
		t.Fatalf("guest stdout = %q, want VENDOR=0x1af4 and DEV=226:128", stdout.String())
	}
}

func TestExtensionLockdownGuardSecondSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows lockdown tests require dedicated job/token setup tested in hostlockdown.
		t.Skip("second-sandbox lockdown subprocess probe runs on Unix hosts")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe, "-test.v", "-test.run=^TestExtensionLockdownSecondSandboxHelper$")
	cmd.Env = append(os.Environ(), "GVX_EXT_LOCKDOWN_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second-sandbox lockdown helper failed: %v\n%s", err, out)
	}
}
