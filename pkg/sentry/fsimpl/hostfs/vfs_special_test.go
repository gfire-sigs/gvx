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

package hostfs

import (
	"os"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// idProvider supplies the unique identifiers that Unix endpoints need.
type idProvider struct{ n atomic.Uint64 }

func (p *idProvider) UniqueID() uint64 { return p.n.Add(1) }

// blockingCtx lets a goroutine block inside the VFS the way a task does. Each
// goroutine that may block needs its own value.
type blockingCtx struct {
	cookieContext
	nt gvcontext.NoTask
}

// BlockOn implements context.Context.BlockOn.
func (c *blockingCtx) BlockOn(w waiter.Waitable, mask waiter.EventMask) bool {
	return c.nt.BlockOn(w, mask)
}

func (e *env) blocking() *blockingCtx {
	return &blockingCtx{cookieContext: e.ctx.(cookieContext)}
}

func (e *env) mknod(p string, mode linux.FileMode, major, minor uint32, ep transport.BoundEndpoint) error {
	return e.vfsObj.MknodAt(e.ctx, e.creds, e.pop(p), &vfs.MknodOptions{Mode: mode, DevMajor: major, DevMinor: minor, Endpoint: ep})
}

func (e *env) mustMknod(p string, mode linux.FileMode) {
	e.t.Helper()
	if err := e.mknod(p, mode, 0, 0, nil); err != nil {
		e.t.Fatalf("mknod %q %#o: %v", p, mode, err)
	}
}

func (e *env) boundEndpoint(p string) (transport.BoundEndpoint, error) {
	return e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop(p), &vfs.BoundEndpointOptions{})
}

// impl returns the filesystem behind the mount of the test.
func (e *env) impl() *filesystem {
	return e.root.Mount().Filesystem().Impl().(*filesystem)
}

// direntTypes lists the dirent type of each entry of the directory p.
func (e *env) direntTypes(p string) map[string]uint8 {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	out := map[string]uint8{}
	err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		out[d.Name] = d.Type
		return nil
	}))
	if err != nil {
		e.t.Fatalf("readdir %q: %v", p, err)
	}
	return out
}

func (e *env) hostSize(p string) int64 {
	e.t.Helper()
	info, err := os.Lstat(e.host(p))
	if err != nil {
		e.t.Fatalf("host stat %q: %v", p, err)
	}
	if !info.Mode().IsRegular() {
		e.t.Fatalf("host file %q has mode %v, want a regular placeholder", p, info.Mode())
	}
	return info.Size()
}

// newListeningEndpoint returns a listening stream endpoint, once as the
// connecting API and once as the bound endpoint that a socket file stores.
func newListeningEndpoint(t *testing.T, ctx gvcontext.Context, ids *idProvider) (transport.Endpoint, transport.BoundEndpoint) {
	t.Helper()
	server := transport.NewConnectioned(ctx, linux.SOCK_STREAM, ids)
	if err := server.Bind(transport.Address{Addr: "/sock"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := server.Listen(ctx, 4); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return server, server.(transport.BoundEndpoint)
}

func TestMknodSocketConnectsThroughBoundEndpointAt(t *testing.T) {
	e := newEnv(t)
	ids := &idProvider{}
	server, bep := newListeningEndpoint(t, e.ctx, ids)
	if err := e.mknod("sock", linux.S_IFSOCK|0o755, 0, 0, bep); err != nil {
		t.Fatalf("mknod socket: %v", err)
	}

	st := e.mustStat("sock")
	if st.Mode&linux.S_IFMT != linux.S_IFSOCK || st.Mode&0o7777 != 0o755 || st.Size != 0 {
		t.Fatalf("stat = mode %#o size %d, want a socket of mode 0755 and size 0", st.Mode, st.Size)
	}
	if got := e.hostSize("sock"); got != 0 {
		t.Fatalf("host placeholder holds %d bytes, want 0", got)
	}
	if got := e.readdir("."); len(got) != 1 || got[0] != "sock" {
		t.Fatalf("readdir = %v, want [sock]", got)
	}
	if got := e.direntTypes(".")["sock"]; got != linux.DT_SOCK {
		t.Fatalf("dirent type = %d, want DT_SOCK", got)
	}

	bound, err := e.boundEndpoint("sock")
	if err != nil {
		t.Fatalf("BoundEndpointAt: %v", err)
	}
	if bound != bep {
		t.Fatalf("BoundEndpointAt returned another endpoint than the one that mknod stored")
	}
	client := transport.NewConnectioned(e.ctx, linux.SOCK_STREAM, ids)
	if serr := client.Connect(e.ctx, bound); serr != nil {
		t.Fatalf("Connect through the socket file: %v", serr)
	}
	peer, serr := server.Accept(e.ctx, nil)
	if serr != nil {
		t.Fatalf("Accept: %v", serr)
	}
	if n, _, serr := client.SendMsg(e.ctx, [][]byte{[]byte("ping")}, transport.ControlMessages{}, nil); serr != nil || n != 4 {
		t.Fatalf("SendMsg = (%d, %v), want 4 bytes", n, serr)
	}
	buf := make([]byte, 16)
	out, _, serr := peer.RecvMsg(e.ctx, [][]byte{buf}, transport.RecvArgs{})
	if serr != nil || string(buf[:out.RecvLen]) != "ping" {
		t.Fatalf("RecvMsg = (%q, %v), want ping", buf[:out.RecvLen], serr)
	}

	_, err = e.open("sock", linux.O_RDONLY, 0)
	wantErrno(t, "open of a socket file", err, linuxerr.ENXIO)
}

func TestSocketKeepsItsEndpointAcrossRenameLinkAndPruning(t *testing.T) {
	e := newEnv(t)
	_, want := newListeningEndpoint(t, e.ctx, &idProvider{})
	if err := e.mknod("sock", linux.S_IFSOCK|0o777, 0, 0, want); err != nil {
		t.Fatal(err)
	}
	// want is the endpoint that every name of the socket must return.
	check := func(path string) {
		t.Helper()
		got, err := e.boundEndpoint(path)
		if err != nil || got != want {
			t.Fatalf("BoundEndpointAt(%q) = (%v, %v), want the stored endpoint", path, got, err)
		}
	}

	if err := e.rename("sock", "renamed"); err != nil {
		t.Fatal(err)
	}
	check("renamed")
	wantErrno(t, "BoundEndpointAt of the old name", func() error { _, err := e.boundEndpoint("sock"); return err }(), linuxerr.ENOENT)

	if err := e.link("renamed", "alias"); err != nil {
		t.Fatalf("link of a socket file: %v", err)
	}
	check("alias")
	if a, b := e.mustStat("renamed"), e.mustStat("alias"); a.Ino != b.Ino || a.Nlink != 2 {
		t.Fatalf("stat = (ino %d, nlink %d) and ino %d, want one inode with 2 links", a.Ino, a.Nlink, b.Ino)
	}

	// The cache must not drop a dentry that holds an endpoint.
	fs := e.impl()
	fs.mu.Lock()
	fs.pruneLocked(fs.root)
	fs.mu.Unlock()
	check("renamed")
	check("alias")

	// Removing one name keeps the endpoint on the other.
	if err := e.unlink("renamed"); err != nil {
		t.Fatal(err)
	}
	check("alias")
}

func TestUnlinkOfSocketRemovesPlaceholderAndRecord(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("sock", linux.S_IFSOCK|0o600)
	if err := e.unlink("sock"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := os.Lstat(e.host("sock")); !os.IsNotExist(err) {
		t.Fatalf("host placeholder after unlink: %v, want it removed", err)
	}
	e.ws.mu.RLock()
	_, ok := e.ws.meta["sock"]
	e.ws.mu.RUnlock()
	if ok {
		t.Fatalf("the .gvx_meta record of the socket survived the unlink")
	}
	_, err := e.stat("sock")
	wantErrno(t, "stat after unlink", err, linuxerr.ENOENT)
	// The name is free again.
	e.mustMknod("sock", linux.S_IFIFO|0o600)
	if st := e.mustStat("sock"); st.Mode&linux.S_IFMT != linux.S_IFIFO {
		t.Fatalf("recreated node has type %#o, want a FIFO", st.Mode&linux.S_IFMT)
	}
}

func TestSocketWithoutEndpointRefusesConnections(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("stale", linux.S_IFSOCK|0o777)
	e.mustMknod("fifo", linux.S_IFIFO|0o666)
	e.writeFile("file", []byte("x"))
	for _, p := range []string{"stale", "fifo", "file"} {
		_, err := e.boundEndpoint(p)
		wantErrno(t, "BoundEndpointAt of "+p, err, linuxerr.ECONNREFUSED)
	}
	_, err := e.boundEndpoint("missing")
	wantErrno(t, "BoundEndpointAt of a missing name", err, linuxerr.ENOENT)
}

func TestSpecialNodesPersistAcrossReopen(t *testing.T) {
	dir := resolvedTempDir(t)
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	_, bep := newListeningEndpoint(t, e.ctx, &idProvider{})
	if err := e.mknod("sock", linux.S_IFSOCK|0o751, 0, 0, bep); err != nil {
		t.Fatal(err)
	}
	e.mustMknod("fifo", linux.S_IFIFO|0o640)
	if err := e.mknod("tty", linux.S_IFCHR|0o620, 4, 7, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.mknod("disk", linux.S_IFBLK|0o660, 8, 1, nil); err != nil {
		t.Fatal(err)
	}
	e.mustMkdir("dir")
	if err := e.mknod("dir/nested", linux.S_IFIFO|0o600, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	closeEnv()

	e2, _ := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	for _, tc := range []struct {
		path         string
		typ          uint16
		perm         uint16
		major, minor uint32
	}{
		{"sock", linux.S_IFSOCK, 0o751, 0, 0},
		{"fifo", linux.S_IFIFO, 0o640, 0, 0},
		{"tty", linux.S_IFCHR, 0o620, 4, 7},
		{"disk", linux.S_IFBLK, 0o660, 8, 1},
		{"dir/nested", linux.S_IFIFO, 0o600, 0, 0},
	} {
		st := e2.mustStat(tc.path)
		if st.Mode&linux.S_IFMT != tc.typ || st.Mode&0o7777 != tc.perm || st.RdevMajor != tc.major || st.RdevMinor != tc.minor {
			t.Errorf("stat %q after reopen = type %#o perm %#o rdev %d:%d, want %#o %#o %d:%d",
				tc.path, st.Mode&linux.S_IFMT, st.Mode&0o7777, st.RdevMajor, st.RdevMinor, tc.typ, tc.perm, tc.major, tc.minor)
		}
	}
	// The endpoint of the earlier mount is gone.
	_, err := e2.boundEndpoint("sock")
	wantErrno(t, "BoundEndpointAt after reopen", err, linuxerr.ECONNREFUSED)
	// A FIFO of the earlier mount opens with an empty pipe.
	fd, err := e2.open("fifo", linux.O_RDONLY|linux.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open FIFO after reopen: %v", err)
	}
	fd.DecRef(e2.ctx)
	types := e2.direntTypes(".")
	for name, want := range map[string]uint8{"sock": linux.DT_SOCK, "fifo": linux.DT_FIFO, "tty": linux.DT_CHR, "disk": linux.DT_BLK, "dir": linux.DT_DIR} {
		if types[name] != want {
			t.Errorf("dirent type of %q = %d, want %d", name, types[name], want)
		}
	}
}

func TestFIFOTransfersDataBetweenDescriptors(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o644)
	if st := e.mustStat("fifo"); st.Mode&linux.S_IFMT != linux.S_IFIFO || st.Size != 0 {
		t.Fatalf("stat = mode %#o size %d, want an empty FIFO", st.Mode, st.Size)
	}
	if got := e.direntTypes(".")["fifo"]; got != linux.DT_FIFO {
		t.Fatalf("dirent type = %d, want DT_FIFO", got)
	}

	// A non-blocking open for writing fails while no reader exists.
	_, err := e.open("fifo", linux.O_WRONLY|linux.O_NONBLOCK, 0)
	wantErrno(t, "O_WRONLY|O_NONBLOCK without a reader", err, linuxerr.ENXIO)

	// A non-blocking open for reading succeeds without a writer.
	reader := e.mustOpen("fifo", linux.O_RDONLY|linux.O_NONBLOCK)
	defer reader.DecRef(e.ctx)
	dst := make([]byte, 16)
	writer := e.mustOpen("fifo", linux.O_WRONLY|linux.O_NONBLOCK)
	defer writer.DecRef(e.ctx)
	_, err = reader.Read(e.ctx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	wantErrno(t, "read of an empty FIFO with a writer", err, linuxerr.ErrWouldBlock)
	if n, err := writer.Write(e.ctx, usermem.BytesIOSequence([]byte("through memory")), vfs.WriteOptions{}); err != nil || n != 14 {
		t.Fatalf("write to the FIFO = (%d, %v), want 14 bytes", n, err)
	}
	n, err := reader.Read(e.ctx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	if err != nil || string(dst[:n]) != "through memory" {
		t.Fatalf("read from the FIFO = (%q, %v), want the written bytes", dst[:n], err)
	}
	if got := e.hostSize("fifo"); got != 0 {
		t.Fatalf("the host placeholder holds %d bytes, want 0: FIFO data stays in Sentry memory", got)
	}
}

func TestFIFOBlockingOpenWaitsForTheOtherEnd(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o644)

	type result struct {
		fd  *vfs.FileDescription
		err error
	}
	opened := make(chan result, 1)
	readerCtx := e.blocking()
	go func() {
		fd, err := e.vfsObj.OpenAt(readerCtx, e.creds, e.fpop("fifo"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
		opened <- result{fd, err}
	}()

	// The writer open succeeds once the reader exists. Both opens finish only
	// when each sees the other end.
	writer, err := e.vfsObj.OpenAt(e.blocking(), e.creds, e.fpop("fifo"), &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		t.Fatalf("blocking open for writing: %v", err)
	}
	defer writer.DecRef(e.ctx)
	r := <-opened
	if r.err != nil {
		t.Fatalf("blocking open for reading: %v", r.err)
	}
	defer r.fd.DecRef(e.ctx)

	if _, err := writer.Write(e.ctx, usermem.BytesIOSequence([]byte("hello")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 8)
	n, err := r.fd.Read(readerCtx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	if err != nil || string(dst[:n]) != "hello" {
		t.Fatalf("read = (%q, %v), want hello", dst[:n], err)
	}
}

func TestFIFOReadWriteOpenNeverBlocks(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o644)
	fd := e.mustOpen("fifo", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if _, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("loop")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 8)
	n, err := fd.Read(e.ctx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	if err != nil || string(dst[:n]) != "loop" {
		t.Fatalf("read = (%q, %v), want loop", dst[:n], err)
	}
}

func TestNewFIFODoesNotShareThePipeOfAnUnlinkedOne(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("a", linux.S_IFIFO|0o644)
	reader := e.mustOpen("a", linux.O_RDONLY|linux.O_NONBLOCK)
	defer reader.DecRef(e.ctx)
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	// The host may hand the inode number of a to b. Opening b for writing
	// must still find no reader, because the reader belongs to the old pipe.
	e.mustMknod("b", linux.S_IFIFO|0o644)
	_, err := e.open("b", linux.O_WRONLY|linux.O_NONBLOCK, 0)
	wantErrno(t, "O_WRONLY|O_NONBLOCK on a new FIFO", err, linuxerr.ENXIO)
}

type stubDevice struct{ err error }

func (d stubDevice) Open(gvcontext.Context, *vfs.Mount, *vfs.Dentry, vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, d.err
}

func TestMknodDeviceNodes(t *testing.T) {
	e := newEnv(t)
	if err := e.mknod("null", linux.S_IFCHR|0o666, 1, 3, nil); err != nil {
		t.Fatalf("mknod char device: %v", err)
	}
	if err := e.mknod("sda", linux.S_IFBLK|0o660, 8, 0, nil); err != nil {
		t.Fatalf("mknod block device: %v", err)
	}
	st := e.mustStat("null")
	if st.Mode&linux.S_IFMT != linux.S_IFCHR || st.Mode&0o7777 != 0o666 || st.RdevMajor != 1 || st.RdevMinor != 3 {
		t.Fatalf("stat null = type %#o perm %#o rdev %d:%d, want a 0666 character device 1:3", st.Mode&linux.S_IFMT, st.Mode&0o7777, st.RdevMajor, st.RdevMinor)
	}
	st = e.mustStat("sda")
	if st.Mode&linux.S_IFMT != linux.S_IFBLK || st.RdevMajor != 8 || st.RdevMinor != 0 {
		t.Fatalf("stat sda = type %#o rdev %d:%d, want a block device 8:0", st.Mode&linux.S_IFMT, st.RdevMajor, st.RdevMinor)
	}
	if got := e.hostSize("null"); got != 0 {
		t.Fatalf("host placeholder of a device holds %d bytes", got)
	}

	// No device is registered, so open fails as it does on other filesystems.
	_, err := e.open("null", linux.O_RDONLY, 0)
	wantErrno(t, "open of an unregistered device", err, linuxerr.ENXIO)

	// A registered device receives the open.
	if err := e.vfsObj.RegisterDevice(vfs.CharDevice, 1, 3, stubDevice{err: linuxerr.EIO}, &vfs.RegisterDeviceOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err = e.open("null", linux.O_RDONLY, 0)
	wantErrno(t, "open of a registered device", err, linuxerr.EIO)

	wantErrno(t, "mknod with a major above the limit", e.mknod("big", linux.S_IFCHR|0o600, rdevMajorMax+1, 0, nil), linuxerr.EINVAL)
	wantErrno(t, "mknod of a directory", e.mknod("d", linux.S_IFDIR|0o755, 0, 0, nil), linuxerr.EINVAL)
	wantErrno(t, "mknod over an existing name", e.mknod("null", linux.S_IFIFO|0o600, 0, 0, nil), linuxerr.EEXIST)
}

func TestWhiteoutRecordIsACharacterDeviceZero(t *testing.T) {
	e := newEnv(t)
	e.ws.mu.Lock()
	err := e.ws.createWhiteoutLocked("gone")
	e.ws.mu.Unlock()
	if err != nil {
		t.Fatalf("createWhiteoutLocked: %v", err)
	}
	st := e.mustStat("gone")
	if st.Mode&linux.S_IFMT != linux.S_IFCHR || st.Mode&0o7777 != 0 || st.RdevMajor != 0 || st.RdevMinor != 0 {
		t.Fatalf("whiteout stat = type %#o perm %#o rdev %d:%d, want character device 0:0 with mode 0", st.Mode&linux.S_IFMT, st.Mode&0o7777, st.RdevMajor, st.RdevMinor)
	}
	if got := e.hostSize("gone"); got != 0 {
		t.Fatalf("whiteout placeholder holds %d bytes", got)
	}
	e.ws.mu.Lock()
	err = e.ws.createWhiteoutLocked("gone")
	e.ws.mu.Unlock()
	if !os.IsExist(err) {
		t.Fatalf("second whiteout = %v, want an exist error", err)
	}
}

func TestChmodAndChownKeepTheSpecialType(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o600)
	if err := e.setStat("fifo", linux.Statx{Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID, Mode: 0o640, UID: 7, GID: 8}); err != nil {
		t.Fatalf("setstat: %v", err)
	}
	st := e.mustStat("fifo")
	if st.Mode != linux.S_IFIFO|0o640 || st.UID != 7 || st.GID != 8 {
		t.Fatalf("stat = mode %#o uid %d gid %d, want FIFO 0640 owned by 7:8", st.Mode, st.UID, st.GID)
	}
	wantErrno(t, "truncate of a FIFO", e.setStat("fifo", linux.Statx{Mask: linux.STATX_SIZE, Size: 0}), linuxerr.EINVAL)
}

func TestPlaceholderWithHostContentIsARegularFile(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("node", linux.S_IFSOCK|0o600)
	if err := os.WriteFile(e.host("node"), []byte("replaced by a host tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	attr, size, err := e.ws.Stat("node")
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode&linux.S_IFMT != linux.S_IFREG || size == 0 {
		t.Fatalf("Stat = type %#o size %d, want a regular file: the host file has content", attr.Mode&linux.S_IFMT, size)
	}
}

func TestMknodRegularFileStaysAnOrdinaryFile(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("plain", linux.S_IFREG|0o644)
	e.writeFile("plain", []byte("data"))
	if got := e.readFile("plain"); string(got) != "data" {
		t.Fatalf("read = %q", got)
	}
	if st := e.mustStat("plain"); st.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("type = %#o, want a regular file", st.Mode&linux.S_IFMT)
	}
}

func TestMetaTableLimitRefusesNewRecords(t *testing.T) {
	e := newEnvOpts(t, workspaceOptions{coalesce: defaultCoalesceWindow, maxMeta: 5})
	hostOnly := e.host("hostfile")
	if err := os.WriteFile(hostOnly, []byte("h"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"f1", "f2"} {
		e.writeFile(name, []byte("x"))
	}
	e.mustMkdir("d1")
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("l1"), "target"); err != nil {
		t.Fatal(err)
	}
	e.mustMknod("n1", linux.S_IFIFO|0o600)
	e.ws.mu.RLock()
	count := len(e.ws.meta)
	e.ws.mu.RUnlock()
	if count != 5 {
		t.Fatalf("the table holds %d records, want 5", count)
	}

	_, err := e.open("f3", linux.O_CREAT|linux.O_WRONLY, 0o644)
	wantErrno(t, "create at the limit", err, linuxerr.ENOSPC)
	wantErrno(t, "mkdir at the limit", e.mkdir("d2"), linuxerr.ENOSPC)
	wantErrno(t, "symlink at the limit", e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("l2"), "t"), linuxerr.ENOSPC)
	wantErrno(t, "mknod FIFO at the limit", e.mknod("n2", linux.S_IFIFO|0o600, 0, 0, nil), linuxerr.ENOSPC)
	wantErrno(t, "mknod device at the limit", e.mknod("n3", linux.S_IFCHR|0o600, 1, 1, nil), linuxerr.ENOSPC)
	wantErrno(t, "link at the limit", e.link("f1", "f1link"), linuxerr.ENOSPC)
	wantErrno(t, "chmod of a file without a record", e.setStat("hostfile", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}), linuxerr.ENOSPC)
	wantErrno(t, "chown of a file without a record", e.setStat("hostfile", linux.Statx{Mask: linux.STATX_UID, UID: 5}), linuxerr.ENOSPC)
	wantErrno(t, "setxattr on a file without a record", e.setXattr("hostfile", "trusted.k", "v", 0), linuxerr.ENOSPC)

	// A refused mutation leaves no host object behind.
	for _, name := range []string{"f3", "d2", "l2", "n2", "n3", "f1link"} {
		if _, err := os.Lstat(e.host(name)); !os.IsNotExist(err) {
			t.Errorf("host entry %q exists after a refused mutation: %v", name, err)
		}
	}

	// A record that exists needs no room, so its owner can still change it.
	if err := e.setStat("f1", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatalf("chmod of a file with a record at the limit: %v", err)
	}
	// Removing a record makes room again.
	if err := e.unlink("n1"); err != nil {
		t.Fatal(err)
	}
	if err := e.mknod("n2", linux.S_IFIFO|0o600, 0, 0, nil); err != nil {
		t.Fatalf("mknod after an unlink made room: %v", err)
	}
}

func TestHostWatcherSuppressesEchoOfSpecialNodes(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.settle()
	hw := &w.ws.watch

	// Prove first that the bridge is live, so that the checks below mean
	// something.
	hostWrite(t, w.host("d/probe"), "p")
	w.sync()
	w.expect("probe", "CREATE probe")
	w.settle()
	base := hw.delivered.Load()

	step := func(what string, op func()) {
		t.Helper()
		op()
		// The guest events arrive without a scan. The scan that follows
		// must add nothing.
		w.drain()
		w.sync()
		w.expectNone("echo of " + what)
		if got := hw.delivered.Load(); got != base {
			t.Fatalf("%s: the watcher delivered %d notifications for a guest mutation", what, got-base)
		}
	}
	step("mknod of a socket", func() {
		_, bep := newListeningEndpoint(t, w.env.ctx, &idProvider{})
		if err := w.mknod("d/sock", linux.S_IFSOCK|0o600, 0, 0, bep); err != nil {
			t.Fatal(err)
		}
	})
	step("mknod of a FIFO", func() { w.mustMknod("d/fifo", linux.S_IFIFO|0o600) })
	step("mknod of a device", func() {
		if err := w.mknod("d/dev", linux.S_IFCHR|0o600, 1, 3, nil); err != nil {
			t.Fatal(err)
		}
	})
	step("whiteout", func() {
		w.ws.mu.Lock()
		defer w.ws.mu.Unlock()
		if err := w.ws.createWhiteoutLocked("d/white"); err != nil {
			t.Fatal(err)
		}
	})
	step("rename of a FIFO", func() {
		if err := w.rename("d/fifo", "d/fifo2"); err != nil {
			t.Fatal(err)
		}
	})
	step("hard link of a socket", func() {
		if err := w.link("d/sock", "d/sock2"); err != nil {
			t.Fatal(err)
		}
	})
	step("unlink of a socket", func() {
		if err := w.unlink("d/sock"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMknodOnAReadOnlyWorkspace(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	for name, mode := range map[string]linux.FileMode{"sock": linux.S_IFSOCK | 0o600, "fifo": linux.S_IFIFO | 0o600, "dev": linux.S_IFCHR | 0o600} {
		wantErrno(t, "mknod "+name+" on a read-only workspace", e.mknod(name, mode, 1, 1, nil), linuxerr.EROFS)
		if _, err := os.Lstat(e.host(name)); !os.IsNotExist(err) {
			t.Errorf("host entry %q exists after a refused mknod: %v", name, err)
		}
	}
}
