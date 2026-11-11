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

package proc

import (
	"bytes"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
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
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/usermem"
)

type fixedProcClock struct{}

func (fixedProcClock) Now() ktime.Time { return ktime.FromNanoseconds(1_700_000_000_000_000_000) }
func (fixedProcClock) NewTimer(ktime.Listener) ktime.Timer {
	panic("fixedProcClock has no timers")
}

func newProcTestStack(t *testing.T) *netstack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() { s.Close() })
	if err := s.CreateNICWithOptions(tcpip.NICID(1), loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("CreateNICWithOptions(lo): %v", err)
	}
	return netstack.NewStack(s, 1)
}

func newProcStateCtx(k *kernel.Kernel, creds *auth.Credentials, st inet.Stack) context.Context {
	vals := map[any]any{
		kernel.CtxKernel:          k,
		auth.CtxCredentials:       creds,
		ktime.CtxRealtimeClock:    fixedProcClock{},
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	}
	if st != nil {
		vals[inet.CtxStack] = st
	}
	return context.WithValues(context.Background(), vals)
}

func readProcFD(t *testing.T, ctx context.Context, fd *vfs.FileDescription) string {
	t.Helper()
	buf := make([]byte, 8192)
	n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("PRead: %v", err)
	}
	return string(buf[:n])
}

func readProcPath(t *testing.T, ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path string) string {
	t.Helper()
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(%s, O_RDONLY): %v", path, err)
	}
	defer fd.DecRef(ctx)
	return readProcFD(t, ctx, fd)
}

func writeProcPath(t *testing.T, ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path, text string) {
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

func buildPopulatedTier2SysDir(ctx context.Context, procfs *filesystem, creds *auth.Credentials, k *kernel.Kernel, st inet.Stack, path string) kernfs.Inode {
	dir := procfs.newLazySysDir(ctx, creds, nil, path).(*lazySysDir)
	subdirs := sysSubdirs(path)
	children := make(map[string]kernfs.Inode, len(subdirs))
	if xplatFiles, ok := procfs.sysNetXplatFiles(ctx, creds, st, path); ok {
		for name, inode := range xplatFiles {
			children[name] = inode
		}
	}
	procfs.addNodeSysctlFiles(ctx, creds, k, st, path, children)
	for _, name := range subdirs {
		subdir := name
		if path != "" {
			subdir = path + "/" + name
		}
		children[name] = buildPopulatedTier2SysDir(ctx, procfs, creds, k, st, subdir)
	}
	dir.OrderedChildren.Populate(children)
	dir.populated.Store(true)
	if st != nil && (path == netIPv4ConfPath || path == netIPv6ConfPath || path == netIPv4NeighPath) {
		return &netConfDir{lazySysDir: dir, stack: st}
	}
	return dir
}

func TestProcTier2NodesAndOpenFDsSaveLoadRoundTrip(t *testing.T) {
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	kOrig := &kernel.Kernel{}
	stOrig := newProcTestStack(t)
	ctx := newProcStateCtx(kOrig, creds, stOrig)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	if err := kOrig.VFS().Init(ctx); err != nil {
		t.Fatalf("kOrig.VFS().Init: %v", err)
	}
	t.Cleanup(func() { kOrig.VFS().Release(ctx) })
	testDisk(t, blockdev.Of(kOrig.VFS()), 2048)

	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		t.Fatalf("GetAnonBlockDevMinor: %v", err)
	}
	procfs := &filesystem{devMinor: devMinor}
	procfs.MaxCachedDentries = defaultMaxCachedDentries
	procfs.NoNegativeDentries = true
	ft := FilesystemType{}
	procfs.VFSFilesystem().Init(vfsObj, &ft, procfs)

	rootInode := procfs.newStaticDir(ctx, creds, map[string]kernfs.Inode{
		"sys":        buildPopulatedTier2SysDir(ctx, procfs, creds, kOrig, stOrig, ""),
		"diskstats":  procfs.newInode(ctx, creds, 0444, &diskstatsData{}),
		"partitions": procfs.newInode(ctx, creds, 0444, &partitionsData{}),
	})
	var rootD kernfs.Dentry
	rootD.InitRoot(&procfs.Filesystem, rootInode)
	mnt := vfsObj.NewDisconnectedMount(procfs.VFSFilesystem(), rootD.VFSDentry(), &vfs.MountOptions{})
	root := vfs.MakeVirtualDentry(mnt, rootD.VFSDentry())
	root.IncRef()
	t.Cleanup(func() {
		root.DecRef(ctx)
		mnt.DecRef(ctx)
		procfs.VFSFilesystem().DecRef(ctx)
		vfsObj.Release(ctx)
	})

	// Exercise Tier 2 sysctl and dynamic node families before checkpointing.
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/vm/overcommit_memory", "1\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/kernel/keys/root_maxkeys", "65536\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/kernel/printk_devkmsg", "on\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/kernel/dmesg_restrict", "1\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/tcp_keepalive_time", "120\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/neigh/default/gc_thresh3", "4096\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/netfilter/nf_conntrack_max", "8192\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/conf/all/rp_filter", "1\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/conf/lo/rp_filter", "2\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/conf/all/forwarding", "1\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/conf/lo/arp_ignore", "2\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv6/conf/lo/accept_ra", "2\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/ipv4/conf/lo/route_localnet", "1\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/bridge/bridge-nf-call-arptables", "0\n")
	writeProcPath(t, ctx, vfsObj, creds, root, "/sys/net/bridge/bridge-nf-call-iptables", "0\n")

	openPaths := []string{
		"/sys/vm/overcommit_memory",
		"/sys/kernel/printk_devkmsg",
		"/sys/net/ipv4/tcp_keepalive_time",
		"/sys/net/netfilter/nf_conntrack_max",
		"/sys/net/ipv4/conf/lo/rp_filter",
		"/sys/net/ipv4/conf/lo/arp_ignore",
		"/sys/net/ipv4/conf/lo/route_localnet",
		"/sys/net/bridge/bridge-nf-call-arptables",
		"/sys/net/bridge/bridge-nf-call-iptables",
		"/diskstats",
		"/partitions",
	}
	openFDs := make([]*vfs.FileDescription, len(openPaths))
	for i, p := range openPaths {
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p)}
		fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDWR})
		if err != nil {
			fd, err = vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		}
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
	klogOrig := kOrig.KernelLog()
	bundle := []any{vfsObj, procfs.VFSFilesystem(), mnt, root, creds, stOrig, klogOrig, openFDs}
	var saveBuf bytes.Buffer
	if _, err := state.Save(ctx, &saveBuf, &bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	kRestored := &kernel.Kernel{}
	stRestoredNet := newProcTestStack(t)
	loadCtx := newProcStateCtx(kRestored, creds, stRestoredNet)
	var loaded []any
	if _, err := state.Load(loadCtx, &saveBuf, &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredVFS := loaded[0].(*vfs.VirtualFilesystem)
	restoredVFSFS := loaded[1].(*vfs.Filesystem)
	restoredMnt := loaded[2].(*vfs.Mount)
	restoredRoot := loaded[3].(vfs.VirtualDentry)
	restoredCreds := loaded[4].(*auth.Credentials)
	restoredStack := loaded[5].(*netstack.Stack)
	restoredFDs := loaded[7].([]*vfs.FileDescription)
	t.Cleanup(func() { restoredStack.Stack.Close() })
	restoredStack.Stack.ResetConfig()
	restoredStack.Stack.ReplaceConfig(stRestoredNet.Stack)
	restoredStack.Stack.Restore()

	// Populate per-stack sysctls on the restored stack and register a disk on kRestored.VFS()
	// so both restored open FDs and freshly opened paths read live state.
	loadCtx = newProcStateCtx(kRestored, restoredCreds, restoredStack)
	if err := kRestored.VFS().Init(loadCtx); err != nil {
		t.Fatalf("kRestored.VFS().Init: %v", err)
	}
	t.Cleanup(func() { kRestored.VFS().Release(loadCtx) })
	testDisk(t, blockdev.Of(kRestored.VFS()), 4096)

	if err := restoredVFS.CompleteRestore(loadCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	t.Cleanup(func() {
		for _, fd := range restoredFDs {
			fd.DecRef(loadCtx)
		}
		restoredRoot.DecRef(loadCtx)
		restoredMnt.DecRef(loadCtx)
		restoredVFSFS.DecRef(loadCtx)
		restoredVFS.Release(loadCtx)
	})

	// Verify reading and writing directly through restored open FDs!
	if got := readProcFD(t, loadCtx, restoredFDs[0]); got != "1\n" {
		t.Errorf("restored open FD /sys/vm/overcommit_memory = %q, want \"1\\n\"", got)
	}
	if _, err := restoredFDs[0].PWrite(loadCtx, usermem.BytesIOSequence([]byte("2\n")), 0, vfs.WriteOptions{}); err != nil {
		t.Fatalf("PWrite on restored open FD /sys/vm/overcommit_memory: %v", err)
	}
	if got := readProcPath(t, loadCtx, restoredVFS, restoredCreds, restoredRoot, "/sys/vm/overcommit_memory"); got != "2\n" {
		t.Errorf("fresh read after PWrite on restored FD = %q, want \"2\\n\"", got)
	}
	if got := readProcPath(t, loadCtx, restoredVFS, restoredCreds, restoredRoot, "/sys/kernel/keys/root_maxkeys"); got != "65536\n" {
		t.Errorf("/sys/kernel/keys/root_maxkeys after restore = %q, want \"65536\\n\"", got)
	}
	if got := readProcFD(t, loadCtx, restoredFDs[1]); got != "on\n" {
		t.Errorf("restored open FD /sys/kernel/printk_devkmsg = %q, want \"on\\n\"", got)
	}
	if got := readProcPath(t, loadCtx, restoredVFS, restoredCreds, restoredRoot, "/sys/kernel/dmesg_restrict"); got != "1\n" {
		t.Errorf("/sys/kernel/dmesg_restrict after restore = %q, want \"1\\n\"", got)
	}
	if got := readProcFD(t, loadCtx, restoredFDs[7]); got != "0\n" {
		t.Errorf("restored open FD /sys/net/bridge/bridge-nf-call-arptables = %q, want \"0\\n\"", got)
	}
	if got := readProcPath(t, loadCtx, restoredVFS, restoredCreds, restoredRoot, "/sys/net/netfilter/nf_conntrack_buckets"); got == "" {
		t.Error("/sys/net/netfilter/nf_conntrack_buckets returned empty output after restore")
	}

	// Verify restored network-backed sysctl FDs accept writes and reflect them on fresh reads.
	if _, err := restoredFDs[2].PWrite(loadCtx, usermem.BytesIOSequence([]byte("90\n")), 0, vfs.WriteOptions{}); err != nil {
		t.Fatalf("PWrite on restored tcp_keepalive_time FD: %v", err)
	}
	if got := readProcFD(t, loadCtx, restoredFDs[2]); got != "90\n" {
		t.Errorf("restored tcp_keepalive_time FD = %q, want \"90\\n\"", got)
	}
	if _, err := restoredFDs[4].PWrite(loadCtx, usermem.BytesIOSequence([]byte("2\n")), 0, vfs.WriteOptions{}); err != nil {
		t.Fatalf("PWrite on restored lo/rp_filter FD: %v", err)
	}
	if got := readProcPath(t, loadCtx, restoredVFS, restoredCreds, restoredRoot, "/sys/net/ipv4/conf/lo/rp_filter"); got != "2\n" {
		t.Errorf("/sys/net/ipv4/conf/lo/rp_filter after restore = %q, want \"2\\n\"", got)
	}

	// Verify restored open FDs for /diskstats and /partitions read from kRestored's blockdev registry.
	if got := readProcFD(t, loadCtx, restoredFDs[9]); !strings.Contains(got, " vda ") {
		t.Errorf("restored open FD /diskstats = %q, want vda entry", got)
	}
	if got := readProcFD(t, loadCtx, restoredFDs[10]); !strings.Contains(got, " 2048 vda\n") {
		t.Errorf("restored open FD /partitions = %q, want 2048 KiB vda entry", got)
	}
}
