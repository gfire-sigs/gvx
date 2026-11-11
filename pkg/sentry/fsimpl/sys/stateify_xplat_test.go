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

package sys_test

import (
	"bytes"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/usermem"
)

func newSysTestStack(t *testing.T) *netstack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	t.Cleanup(func() { s.Close() })
	if err := s.CreateNICWithOptions(tcpip.NICID(1), loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("CreateNICWithOptions(lo): %v", err)
	}
	return netstack.NewStack(s, 1)
}

func newSysStateCtx(k *kernel.Kernel, creds *auth.Credentials, st inet.Stack) gvcontext.Context {
	return gvcontext.WithValues(gvcontext.Background(), map[any]any{
		kernel.CtxKernel:          k,
		inet.CtxStack:             st,
		ktime.CtxRealtimeClock:    fixedClock{},
		auth.CtxCredentials:       creds,
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	})
}

func readSysFD(t *testing.T, ctx gvcontext.Context, fd *vfs.FileDescription) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("PRead: %v", err)
	}
	return string(buf[:n])
}

func readSysPath(t *testing.T, ctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path string) string {
	t.Helper()
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(%s, O_RDONLY): %v", path, err)
	}
	defer fd.DecRef(ctx)
	return readSysFD(t, ctx, fd)
}

func writeSysPath(t *testing.T, ctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path, text string) {
	t.Helper()
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		t.Fatalf("OpenAt(%s, O_WRONLY): %v", path, err)
	}
	defer fd.DecRef(ctx)
	if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte(text)), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(%s, %q): %v", path, text, err)
	}
}

func addSysTestDisk(t *testing.T, r *blockdev.Registry, sectors uint64) {
	t.Helper()
	stats := blockdev.NewStats(func() int64 { return 0 })
	req := stats.Begin()
	stats.End(blockdev.Read, req, 4096)
	if _, err := r.Add(blockdev.Options{Stats: stats, Sectors: func() uint64 { return sectors }}); err != nil {
		t.Fatalf("blockdev.Add: %v", err)
	}
}

func TestSysfsAndBPFFSTier2NodesSaveLoadRoundTrip(t *testing.T) {
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	kOrig := &kernel.Kernel{}
	stOrig := newSysTestStack(t)
	ctx := newSysStateCtx(kOrig, creds, stOrig)

	if err := kOrig.VFS().Init(ctx); err != nil {
		t.Fatalf("kOrig.VFS().Init: %v", err)
	}
	t.Cleanup(func() { kOrig.VFS().Release(ctx) })
	addSysTestDisk(t, blockdev.Of(kOrig.VFS()), 4096)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(sys.Name, sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	vfsObj.MustRegisterFilesystemType(sys.BPFName, sys.BPFFilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})

	sysFS, sysRootD, err := (sys.FilesystemType{}).GetFilesystem(ctx, vfsObj, creds, "", vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("sys.FilesystemType.GetFilesystem: %v", err)
	}
	sysMnt := vfsObj.NewDisconnectedMount(sysFS, sysRootD, &vfs.MountOptions{})
	sysRoot := vfs.MakeVirtualDentry(sysMnt, sysRootD)
	sysRoot.IncRef()

	bpfFS, bpfRootD, err := (sys.BPFFilesystemType{}).GetFilesystem(ctx, vfsObj, creds, "", vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("sys.BPFFilesystemType.GetFilesystem: %v", err)
	}
	bpfMnt := vfsObj.NewDisconnectedMount(bpfFS, bpfRootD, &vfs.MountOptions{})
	bpfRoot := vfs.MakeVirtualDentry(bpfMnt, bpfRootD)
	bpfRoot.IncRef()

	t.Cleanup(func() {
		bpfRoot.DecRef(ctx)
		bpfMnt.DecRef(ctx)
		bpfFS.DecRef(ctx)
		sysRoot.DecRef(ctx)
		sysMnt.DecRef(ctx)
		sysFS.DecRef(ctx)
		vfsObj.Release(ctx)
	})

	// Create a directory inside bpffs before save.
	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{Root: bpfRoot, Start: bpfRoot, Path: fspath.Parse("/pinned")}, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt(bpffs /pinned): %v", err)
	}

	// Write custom values to Tier 2 module parameter files.
	writeSysPath(t, ctx, vfsObj, creds, sysRoot, "/module/nf_conntrack/parameters/hashsize", "32768\n")
	writeSysPath(t, ctx, vfsObj, creds, sysRoot, "/module/ip_set/parameters/max_sets", "512\n")
	writeSysPath(t, ctx, vfsObj, creds, sysRoot, "/module/xt_recent/parameters/ip_list_tot", "250\n")

	// Open FDs across block, net, and module parameter nodes before save.
	openPaths := []string{
		"/block/vda/size",
		"/block/vda/stat",
		"/dev/block/254:0/dev",
		"/class/net/lo/operstate",
		"/class/net/lo/mtu",
		"/class/net/lo/statistics/rx_bytes",
		"/module/nf_conntrack/parameters/hashsize",
		"/module/xt_recent/parameters/ip_list_tot",
	}
	openFDs := make([]*vfs.FileDescription, len(openPaths))
	for i, p := range openPaths {
		pop := &vfs.PathOperation{Root: sysRoot, Start: sysRoot, Path: fspath.Parse(p)}
		fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err != nil {
			t.Fatalf("OpenAt(%s): %v", p, err)
		}
		openFDs[i] = fd
	}
	t.Cleanup(func() {
		for _, fd := range openFDs {
			fd.DecRef(ctx)
		}
	})

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	bundle := []any{vfsObj, sysFS, sysMnt, sysRoot, bpfFS, bpfMnt, bpfRoot, creds, stOrig, openFDs}
	var saveBuf bytes.Buffer
	if _, err := state.Save(ctx, &saveBuf, &bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	kRestored := &kernel.Kernel{}
	stBootstrap := newSysTestStack(t)
	loadCtx := newSysStateCtx(kRestored, creds, stBootstrap)
	var loaded []any
	if _, err := state.Load(loadCtx, &saveBuf, &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredVFS := loaded[0].(*vfs.VirtualFilesystem)
	restoredSysFS := loaded[1].(*vfs.Filesystem)
	restoredSysMnt := loaded[2].(*vfs.Mount)
	restoredSysRoot := loaded[3].(vfs.VirtualDentry)
	restoredBPFFS := loaded[4].(*vfs.Filesystem)
	restoredBPFMnt := loaded[5].(*vfs.Mount)
	restoredBPFRoot := loaded[6].(vfs.VirtualDentry)
	restoredCreds := loaded[7].(*auth.Credentials)
	restoredStack := loaded[8].(*netstack.Stack)
	restoredFDs := loaded[9].([]*vfs.FileDescription)
	t.Cleanup(func() { restoredStack.Stack.Close() })
	restoredStack.Stack.ResetConfig()
	restoredStack.Stack.ReplaceConfig(stBootstrap.Stack)
	restoredStack.Stack.Restore()

	loadCtx = newSysStateCtx(kRestored, restoredCreds, restoredStack)
	if err := kRestored.VFS().Init(loadCtx); err != nil {
		t.Fatalf("kRestored.VFS().Init: %v", err)
	}
	t.Cleanup(func() { kRestored.VFS().Release(loadCtx) })
	addSysTestDisk(t, blockdev.Of(kRestored.VFS()), 8192)
	ipset.ModuleFor(kRestored).SetMaxSets(512)

	if err := restoredVFS.CompleteRestore(loadCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	t.Cleanup(func() {
		for _, fd := range restoredFDs {
			fd.DecRef(loadCtx)
		}
		restoredBPFRoot.DecRef(loadCtx)
		restoredBPFMnt.DecRef(loadCtx)
		restoredBPFFS.DecRef(loadCtx)
		restoredSysRoot.DecRef(loadCtx)
		restoredSysMnt.DecRef(loadCtx)
		restoredSysFS.DecRef(loadCtx)
		restoredVFS.Release(loadCtx)
	})

	// Verify restored open FDs across block, net, and module nodes.
	if got := readSysFD(t, loadCtx, restoredFDs[0]); got != "8192\n" {
		t.Errorf("restored open FD /block/vda/size = %q, want \"8192\\n\"", got)
	}
	if fields := strings.Fields(readSysFD(t, loadCtx, restoredFDs[1])); len(fields) != blockdev.NumFields || fields[0] != "1" {
		t.Errorf("restored open FD /block/vda/stat fields = %v, want 17 fields starting with 1", fields)
	}
	if got := readSysFD(t, loadCtx, restoredFDs[2]); got != "254:0\n" {
		t.Errorf("restored open FD /dev/block/254:0/dev = %q, want \"254:0\\n\"", got)
	}
	if got := readSysFD(t, loadCtx, restoredFDs[3]); got != "unknown\n" {
		t.Errorf("restored open FD /class/net/lo/operstate = %q, want \"unknown\\n\"", got)
	}
	if got := readSysFD(t, loadCtx, restoredFDs[4]); got != "65536\n" {
		t.Errorf("restored open FD /class/net/lo/mtu = %q, want \"65536\\n\"", got)
	}
	if got := readSysFD(t, loadCtx, restoredFDs[5]); got != "0\n" {
		t.Errorf("restored open FD /class/net/lo/statistics/rx_bytes = %q, want \"0\\n\"", got)
	}
	if got := readSysFD(t, loadCtx, restoredFDs[6]); got != "32768\n" {
		t.Errorf("restored open FD /module/nf_conntrack/parameters/hashsize = %q, want \"32768\\n\"", got)
	}

	// Verify fresh lookups on restored sysfs and bpffs mounts.
	if got := readSysPath(t, loadCtx, restoredVFS, restoredCreds, restoredSysRoot, "/class/block/vda/queue/scheduler"); got != "[none]\n" {
		t.Errorf("/class/block/vda/queue/scheduler = %q, want \"[none]\\n\"", got)
	}
	if got := readSysPath(t, loadCtx, restoredVFS, restoredCreds, restoredSysRoot, "/class/net/lo/ifindex"); got != "1\n" {
		t.Errorf("/class/net/lo/ifindex = %q, want \"1\\n\"", got)
	}
	if got := readSysPath(t, loadCtx, restoredVFS, restoredCreds, restoredSysRoot, "/module/ip_set/parameters/max_sets"); got != "512\n" {
		t.Errorf("/module/ip_set/parameters/max_sets = %q, want \"512\\n\"", got)
	}
	writeSysPath(t, loadCtx, restoredVFS, restoredCreds, restoredSysRoot, "/module/xt_recent/parameters/ip_pkt_list_tot", "40\n")
	if got := readSysPath(t, loadCtx, restoredVFS, restoredCreds, restoredSysRoot, "/module/xt_recent/parameters/ip_pkt_list_tot"); got != "40\n" {
		t.Errorf("/module/xt_recent/parameters/ip_pkt_list_tot = %q, want \"40\\n\"", got)
	}

	stfs, err := restoredVFS.StatFSAt(loadCtx, restoredCreds, &vfs.PathOperation{Root: restoredBPFRoot, Start: restoredBPFRoot, Path: fspath.Parse("/pinned")})
	if err != nil || stfs.Type != bpfFSMagic {
		t.Errorf("StatFSAt(bpffs /pinned) = (%#x, %v), want BPF_FS_MAGIC %#x", stfs.Type, err, bpfFSMagic)
	}
}
