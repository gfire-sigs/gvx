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

package rpcfs

import (
	"bytes"
	goContext "context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

type localRootClient struct {
	mu             sync.Mutex
	root           *os.Root
	closed         bool
	beforeCall     func(ctx goContext.Context, op string) error
	overrideWriteN func() (int64, bool)
}

func (c *localRootClient) mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return linuxerr.ENOENT
	}
	if errors.Is(err, os.ErrExist) {
		return linuxerr.EEXIST
	}
	if errors.Is(err, os.ErrPermission) {
		return linuxerr.EACCES
	}
	return linuxerr.EIO
}

func (c *localRootClient) entryFromInfo(name string, fi os.FileInfo) Entry {
	mode := uint32(fi.Mode().Perm())
	switch {
	case fi.IsDir():
		mode |= linux.S_IFDIR
	case fi.Mode()&os.ModeSymlink != 0:
		mode |= linux.S_IFLNK
	default:
		mode |= linux.S_IFREG
	}
	return Entry{
		Name:    name,
		Mode:    mode,
		Size:    fi.Size(),
		MtimeNS: fi.ModTime().UnixNano(),
		AtimeNS: fi.ModTime().UnixNano(),
		CtimeNS: fi.ModTime().UnixNano(),
	}
}

func (c *localRootClient) checkOpen(ctx goContext.Context, op string) error {
	c.mu.Lock()
	closed := c.closed
	hook := c.beforeCall
	c.mu.Unlock()
	if closed {
		return linuxerr.EIO
	}
	if hook != nil {
		return hook(ctx, op)
	}
	return nil
}

func (c *localRootClient) Stat(ctx goContext.Context, rel string) (Entry, error) {
	if err := c.checkOpen(ctx, "stat"); err != nil {
		return Entry{}, err
	}
	fi, err := c.root.Lstat(rel)
	if err != nil {
		return Entry{}, c.mapErr(err)
	}
	return c.entryFromInfo(filepath.Base(rel), fi), nil
}

func (c *localRootClient) Readdir(ctx goContext.Context, rel string) ([]Entry, error) {
	if err := c.checkOpen(ctx, "readdir"); err != nil {
		return nil, err
	}
	f, err := c.root.Open(rel)
	if err != nil {
		return nil, c.mapErr(err)
	}
	defer f.Close()
	infos, err := f.Readdir(-1)
	if err != nil {
		return nil, c.mapErr(err)
	}
	out := make([]Entry, 0, len(infos))
	for _, fi := range infos {
		out = append(out, c.entryFromInfo(fi.Name(), fi))
	}
	return out, nil
}

func (c *localRootClient) Read(ctx goContext.Context, rel string, offset, length int64) ([]byte, error) {
	if err := c.checkOpen(ctx, "read"); err != nil {
		return nil, err
	}
	f, err := c.root.Open(rel)
	if err != nil {
		return nil, c.mapErr(err)
	}
	defer f.Close()
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, c.mapErr(err)
	}
	return buf[:n], nil
}

func (c *localRootClient) Write(ctx goContext.Context, rel string, offset int64, data []byte) (int64, error) {
	if err := c.checkOpen(ctx, "write"); err != nil {
		return 0, err
	}
	c.mu.Lock()
	ov := c.overrideWriteN
	c.mu.Unlock()
	if ov != nil {
		if n, ok := ov(); ok {
			return n, nil
		}
	}
	f, err := c.root.OpenFile(rel, os.O_WRONLY, 0)
	if err != nil {
		return 0, c.mapErr(err)
	}
	defer f.Close()
	n, err := f.WriteAt(data, offset)
	return int64(n), c.mapErr(err)
}

func (c *localRootClient) Create(ctx goContext.Context, rel string, mode, flags uint32) (Entry, error) {
	if err := c.checkOpen(ctx, "create"); err != nil {
		return Entry{}, err
	}
	oflags := os.O_RDWR | os.O_CREATE
	if flags&linux.O_EXCL != 0 {
		oflags |= os.O_EXCL
	} else {
		oflags |= os.O_TRUNC
	}
	f, err := c.root.OpenFile(rel, oflags, os.FileMode(mode&0o777))
	if err != nil {
		return Entry{}, c.mapErr(err)
	}
	fi, statErr := f.Stat()
	_ = f.Close()
	if statErr != nil {
		return Entry{}, c.mapErr(statErr)
	}
	return c.entryFromInfo(filepath.Base(rel), fi), nil
}

func (c *localRootClient) Mkdir(ctx goContext.Context, rel string, mode uint32) error {
	if err := c.checkOpen(ctx, "mkdir"); err != nil {
		return err
	}
	return c.mapErr(c.root.Mkdir(rel, os.FileMode(mode&0o777)))
}

func (c *localRootClient) Unlink(ctx goContext.Context, rel string) error {
	if err := c.checkOpen(ctx, "unlink"); err != nil {
		return err
	}
	fi, err := c.root.Lstat(rel)
	if err != nil {
		return c.mapErr(err)
	}
	if fi.IsDir() {
		return linuxerr.EISDIR
	}
	return c.mapErr(c.root.Remove(rel))
}

func (c *localRootClient) Rmdir(ctx goContext.Context, rel string) error {
	if err := c.checkOpen(ctx, "rmdir"); err != nil {
		return err
	}
	fi, err := c.root.Lstat(rel)
	if err != nil {
		return c.mapErr(err)
	}
	if !fi.IsDir() {
		return linuxerr.ENOTDIR
	}
	return c.mapErr(c.root.Remove(rel))
}

func (c *localRootClient) Rename(ctx goContext.Context, oldRel, newRel string) error {
	if err := c.checkOpen(ctx, "rename"); err != nil {
		return err
	}
	return c.mapErr(c.root.Rename(oldRel, newRel))
}

func (c *localRootClient) Truncate(ctx goContext.Context, rel string, size int64) error {
	if err := c.checkOpen(ctx, "truncate"); err != nil {
		return err
	}
	f, err := c.root.OpenFile(rel, os.O_WRONLY, 0)
	if err != nil {
		return c.mapErr(err)
	}
	err = f.Truncate(size)
	_ = f.Close()
	return c.mapErr(err)
}

func (c *localRootClient) Chmod(ctx goContext.Context, rel string, mode uint32) error {
	if err := c.checkOpen(ctx, "chmod"); err != nil {
		return err
	}
	return c.mapErr(c.root.Chmod(rel, os.FileMode(mode&0o777)))
}

func (c *localRootClient) Utimens(ctx goContext.Context, rel string, atimeNS, mtimeNS int64, setAtime, setMtime bool) error {
	if err := c.checkOpen(ctx, "utimens"); err != nil {
		return err
	}
	var atime, mtime time.Time
	if setAtime {
		atime = time.Unix(0, atimeNS)
	}
	if setMtime {
		mtime = time.Unix(0, mtimeNS)
	}
	return c.mapErr(c.root.Chtimes(rel, atime, mtime))
}

func (c *localRootClient) Readlink(ctx goContext.Context, rel string) (string, error) {
	if err := c.checkOpen(ctx, "readlink"); err != nil {
		return "", err
	}
	t, err := c.root.Readlink(rel)
	return t, c.mapErr(err)
}

func (c *localRootClient) Symlink(ctx goContext.Context, target, linkRel string) error {
	if err := c.checkOpen(ctx, "symlink"); err != nil {
		return err
	}
	return c.mapErr(c.root.Symlink(target, linkRel))
}

func (c *localRootClient) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.root.Close()
}

type interruptibleCtx struct {
	gvcontext.Context
	cancel chan struct{}
}

func newInterruptibleCtx() *interruptibleCtx {
	return &interruptibleCtx{
		Context: gvcontext.Background(),
		cancel:  make(chan struct{}),
	}
}

func (ic *interruptibleCtx) Interrupt() {
	select {
	case <-ic.cancel:
	default:
		close(ic.cancel)
	}
}

func (ic *interruptibleCtx) Block(ch <-chan struct{}) error {
	select {
	case <-ic.cancel:
		return linuxerr.ErrInterrupted
	case <-ch:
		return nil
	}
}

type testDirCB struct {
	names []string
}

func (cb *testDirCB) Handle(d vfs.Dirent) error {
	cb.names = append(cb.names, d.Name)
	return nil
}

func setupRPCFSMount(t *testing.T, readOnly bool) (string, *localRootClient, *vfs.VirtualFilesystem, vfs.VirtualDentry, gvcontext.Context, *auth.Credentials) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := &localRootClient{root: root}
	t.Cleanup(func() { _ = client.Close() })

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })

	fs, rootD, err := NewFilesystem(ctx, &vfsObj, client, "host-dir", readOnly)
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{ReadOnly: readOnly})
	fs.DecRef(ctx)
	rootVD := vfs.MakeVirtualDentry(mnt, rootD)
	t.Cleanup(func() { rootVD.DecRef(ctx) })
	return dir, client, &vfsObj, rootVD, ctx, creds
}

func TestRPCFSReadWriteAndDisconnectEIO(t *testing.T) {
	_, client, vfsObj, rootVD, ctx, creds := setupRPCFSMount(t, false)
	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse(p)}
	}

	if err := vfsObj.MkdirAt(ctx, creds, pop("/sub"), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt: %v", err)
	}
	fd, err := vfsObj.OpenAt(ctx, creds, pop("/sub/hello.txt"), &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_TRUNC,
		Mode:  0o644,
	})
	if err != nil {
		t.Fatalf("OpenAt create: %v", err)
	}
	payload := []byte("hello-rpcfs")
	if n, err := fd.Write(ctx, usermem.BytesIOSequence(payload), vfs.WriteOptions{}); err != nil || n != int64(len(payload)) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if _, err := fd.Seek(ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	got := make([]byte, len(payload))
	if n, err := fd.Read(ctx, usermem.BytesIOSequence(got), vfs.ReadOptions{}); err != nil || n != int64(len(payload)) {
		t.Fatalf("Read = (%d, %v)", n, err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	fd.DecRef(ctx)

	if got, err := vfsObj.PathnameInFilesystem(ctx, rootVD); err != nil || got != "/" {
		t.Fatalf("PathnameInFilesystem(root) = (%q, %v), want (\"/\", nil)", got, err)
	}

	// Disconnecting the backing client must yield EIO cleanly without panicking.
	_ = client.Close()
	if _, err := vfsObj.StatAt(ctx, creds, pop("/sub/hello.txt"), &vfs.StatOptions{}); err != linuxerr.EIO {
		t.Fatalf("StatAt after client disconnect = %v, want EIO", err)
	}
}

func TestRPCFSFullVFSContractAndRenameRebase(t *testing.T) {
	hostDir, _, vfsObj, rootVD, ctx, creds := setupRPCFSMount(t, false)
	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse(p)}
	}

	// 1. Directory creation, O_CREAT|O_EXCL, and Readdir.
	if err := vfsObj.MkdirAt(ctx, creds, pop("/dirA"), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt /dirA: %v", err)
	}
	fd, err := vfsObj.OpenAt(ctx, creds, pop("/dirA/child.txt"), &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0o644,
	})
	if err != nil {
		t.Fatalf("OpenAt O_CREAT|O_EXCL: %v", err)
	}
	if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte("before-rename")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fd.DecRef(ctx)

	// Duplicate O_CREAT|O_EXCL must fail with EEXIST.
	if dup, err := vfsObj.OpenAt(ctx, creds, pop("/dirA/child.txt"), &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0o644,
	}); !linuxerr.Equals(linuxerr.EEXIST, err) {
		if dup != nil {
			dup.DecRef(ctx)
		}
		t.Fatalf("duplicate O_CREAT|O_EXCL err = %v, want EEXIST", err)
	}

	// Readdir on /dirA must return ".", "..", and "child.txt".
	dirFD, err := vfsObj.OpenAt(ctx, creds, pop("/dirA"), &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		t.Fatalf("OpenAt dir: %v", err)
	}
	var cb testDirCB
	if err := dirFD.IterDirents(ctx, &cb); err != nil {
		t.Fatalf("IterDirents: %v", err)
	}
	dirFD.DecRef(ctx)
	sort.Strings(cb.names)
	if len(cb.names) != 3 || cb.names[0] != "." || cb.names[1] != ".." || cb.names[2] != "child.txt" {
		t.Fatalf("Readdir /dirA = %v, want [. .. child.txt]", cb.names)
	}

	// 2. Rename directory /dirA -> /dirB while /dirA/child.txt is cached in dentries.
	// Subsequent read/write on /dirB/child.txt MUST resolve to dirB/child.txt on host.
	if err := vfsObj.RenameAt(ctx, creds, pop("/dirA"), pop("/dirB"), &vfs.RenameOptions{}); err != nil {
		t.Fatalf("RenameAt /dirA -> /dirB: %v", err)
	}
	fd2, err := vfsObj.OpenAt(ctx, creds, pop("/dirB/child.txt"), &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_TRUNC})
	if err != nil {
		t.Fatalf("OpenAt /dirB/child.txt after dir rename: %v", err)
	}
	if _, err := fd2.Write(ctx, usermem.BytesIOSequence([]byte("after-rename")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write /dirB/child.txt: %v", err)
	}
	fd2.DecRef(ctx)
	gotHost, err := os.ReadFile(filepath.Join(hostDir, "dirB", "child.txt"))
	if err != nil || string(gotHost) != "after-rename" {
		t.Fatalf("host dirB/child.txt = (%q, %v), want after-rename", gotHost, err)
	}

	// 3. SetStatAt: Truncate, Chmod, and Utimens.
	wantTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	if err := vfsObj.SetStatAt(ctx, creds, pop("/dirB/child.txt"), &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask:  linux.STATX_SIZE | linux.STATX_MODE | linux.STATX_MTIME,
			Size:  5,
			Mode:  0o600,
			Mtime: linux.NsecToStatxTimestamp(wantTime.UnixNano()),
		},
	}); err != nil {
		t.Fatalf("SetStatAt: %v", err)
	}
	st, err := vfsObj.StatAt(ctx, creds, pop("/dirB/child.txt"), &vfs.StatOptions{Mask: linux.STATX_ALL})
	if err != nil {
		t.Fatalf("StatAt after SetStat: %v", err)
	}
	if st.Size != 5 {
		t.Fatalf("Size after Truncate = %d, want 5", st.Size)
	}
	if runtime.GOOS != "windows" && st.Mode&0o777 != 0o600 {
		t.Fatalf("Mode after Chmod = %#o, want 0600", st.Mode&0o777)
	}
	if gotSec := st.Mtime.Sec; gotSec != wantTime.Unix() {
		t.Fatalf("Mtime.Sec = %d, want %d", gotSec, wantTime.Unix())
	}

	// 4. SymlinkAt, ReadlinkAt, and OpenAt(O_CREAT) through existing symlink (must NOT return ELOOP).
	if runtime.GOOS != "windows" {
		if err := vfsObj.SymlinkAt(ctx, creds, pop("/dirB/link.txt"), "child.txt"); err != nil {
			t.Fatalf("SymlinkAt: %v", err)
		}
		target, err := vfsObj.ReadlinkAt(ctx, creds, pop("/dirB/link.txt"))
		if err != nil || target != "child.txt" {
			t.Fatalf("ReadlinkAt = (%q, %v), want child.txt", target, err)
		}
		followPop := &vfs.PathOperation{
			Root:               rootVD,
			Start:              rootVD,
			Path:               fspath.Parse("/dirB/link.txt"),
			FollowFinalSymlink: true,
		}
		lfd, err := vfsObj.OpenAt(ctx, creds, followPop, &vfs.OpenOptions{
			Flags: linux.O_RDWR | linux.O_CREAT,
			Mode:  0o644,
		})
		if err != nil {
			t.Fatalf("OpenAt(O_CREAT) through existing symlink failed: %v", err)
		}
		buf := make([]byte, 5)
		n, err := lfd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		lfd.DecRef(ctx)
		if err != nil || string(buf[:n]) != "after" {
			t.Fatalf("Read via symlink = (%q, %v), want after", buf[:n], err)
		}
		// OpenAt with O_NOFOLLOW on a symlink MUST return ELOOP and MUST NOT truncate the target.
		noFollowPop := &vfs.PathOperation{
			Root:               rootVD,
			Start:              rootVD,
			Path:               fspath.Parse("/dirB/link.txt"),
			FollowFinalSymlink: false,
		}
		if f, err := vfsObj.OpenAt(ctx, creds, noFollowPop, &vfs.OpenOptions{
			Flags: linux.O_WRONLY | linux.O_TRUNC | linux.O_NOFOLLOW,
		}); !linuxerr.Equals(linuxerr.ELOOP, err) {
			if f != nil {
				f.DecRef(ctx)
			}
			t.Fatalf("OpenAt(O_NOFOLLOW|O_TRUNC) on symlink = %v, want ELOOP", err)
		}
		// Target file must still be untouched ("after").
		if gotTarget, err := os.ReadFile(filepath.Join(hostDir, "dirB", "child.txt")); err != nil || string(gotTarget) != "after" {
			t.Fatalf("O_NOFOLLOW symlink open clobbered target: (%q, %v)", gotTarget, err)
		}
		// O_PATH|O_NOFOLLOW (GetDentryAt) on symlink still succeeds.
		if vd, err := vfsObj.GetDentryAt(ctx, creds, noFollowPop, &vfs.GetDentryOptions{}); err != nil {
			t.Fatalf("GetDentryAt(FollowFinalSymlink=false) on symlink failed: %v", err)
		} else {
			vd.DecRef(ctx)
		}
		if err := vfsObj.UnlinkAt(ctx, creds, pop("/dirB/link.txt")); err != nil {
			t.Fatalf("UnlinkAt symlink: %v", err)
		}
	}

	// 4b. RenameAt directory into its own descendant must return EINVAL (cycle guard).
	if err := vfsObj.MkdirAt(ctx, creds, pop("/dirB/sub"), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt /dirB/sub: %v", err)
	}
	if err := vfsObj.RenameAt(ctx, creds, pop("/dirB"), pop("/dirB/sub/loop"), &vfs.RenameOptions{}); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("RenameAt /dirB -> /dirB/sub/loop = %v, want EINVAL", err)
	}
	if err := vfsObj.RmdirAt(ctx, creds, pop("/dirB/sub")); err != nil {
		t.Fatalf("RmdirAt /dirB/sub: %v", err)
	}

	// 5. UnlinkAt rejects directories (EISDIR); RmdirAt rejects regular files (ENOTDIR).
	if err := vfsObj.UnlinkAt(ctx, creds, pop("/dirB")); !linuxerr.Equals(linuxerr.EISDIR, err) {
		t.Fatalf("UnlinkAt on dir = %v, want EISDIR", err)
	}
	if err := vfsObj.RmdirAt(ctx, creds, pop("/dirB/child.txt")); !linuxerr.Equals(linuxerr.ENOTDIR, err) {
		t.Fatalf("RmdirAt on file = %v, want ENOTDIR", err)
	}
	if err := vfsObj.UnlinkAt(ctx, creds, pop("/dirB/child.txt")); err != nil {
		t.Fatalf("UnlinkAt file: %v", err)
	}
	if err := vfsObj.RmdirAt(ctx, creds, pop("/dirB")); err != nil {
		t.Fatalf("RmdirAt empty dir: %v", err)
	}

	// 6. Concurrent operations under -race.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p := fmt.Sprintf("/conc-%d.txt", id)
			f, err := vfsObj.OpenAt(ctx, creds, pop(p), &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT | linux.O_TRUNC,
				Mode:  0o644,
			})
			if err != nil {
				errs <- err
				return
			}
			_, werr := f.Write(ctx, usermem.BytesIOSequence([]byte("ok")), vfs.WriteOptions{})
			f.DecRef(ctx)
			if werr != nil {
				errs <- werr
				return
			}
			if _, err := vfsObj.StatAt(ctx, creds, pop(p), &vfs.StatOptions{}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent rpcfs error: %v", err)
	}
}

func TestRPCFSReadOnlyPermissionsBoundsAndInterrupt(t *testing.T) {
	// 1. Immutable readOnly=true rejects writes even if VFS mount options are flipped RW.
	t.Run("immutable_readonly", func(t *testing.T) {
		_, _, vfsObj, rootVD, ctx, creds := setupRPCFSMount(t, true)
		_ = vfsObj.SetMountReadOnly(rootVD.Mount(), false)
		pop := &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse("/blocked.txt")}
		if err := vfsObj.MkdirAt(ctx, creds, pop, &vfs.MkdirOptions{Mode: 0o755}); !linuxerr.Equals(linuxerr.EROFS, err) {
			t.Fatalf("MkdirAt on immutable RO rpcfs = %v, want EROFS", err)
		}
		if f, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_WRONLY | linux.O_CREAT, Mode: 0o644}); !linuxerr.Equals(linuxerr.EROFS, err) {
			if f != nil {
				f.DecRef(ctx)
			}
			t.Fatalf("OpenAt create on immutable RO rpcfs = %v, want EROFS", err)
		}
	})

	// 2. Non-root permission checks, invalid peer Write return bounds, and Interrupt -> EINTR.
	t.Run("permissions_bounds_interrupt", func(t *testing.T) {
		_, client, vfsObj, rootVD, ctx, rootCreds := setupRPCFSMount(t, false)
		pop := func(p string) *vfs.PathOperation {
			return &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse(p)}
		}

		// Create a 0600 file owned by root (UID 0).
		fd, err := vfsObj.OpenAt(ctx, rootCreds, pop("/secret.txt"), &vfs.OpenOptions{
			Flags: linux.O_RDWR | linux.O_CREAT | linux.O_TRUNC,
			Mode:  0o600,
		})
		if err != nil {
			t.Fatalf("create secret.txt: %v", err)
		}
		// Simulate misbehaving peer returning oversized Written (> copied) -> must fail with EIO, never panic.
		client.mu.Lock()
		client.overrideWriteN = func() (int64, bool) { return 99999, true }
		client.mu.Unlock()
		if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte("abc")), vfs.WriteOptions{}); !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("Write with oversized peer return = %v, want EIO", err)
		}
		client.mu.Lock()
		client.overrideWriteN = func() (int64, bool) { return -1, true }
		client.mu.Unlock()
		if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte("abc")), vfs.WriteOptions{}); !linuxerr.Equals(linuxerr.EIO, err) {
			t.Fatalf("Write with negative peer return = %v, want EIO", err)
		}
		client.mu.Lock()
		client.overrideWriteN = nil
		client.mu.Unlock()
		fd.DecRef(ctx)

		// Non-root user must receive EACCES when opening 0600 file on Unix.
		if runtime.GOOS != "windows" {
			userCreds := auth.NewUserCredentials(1000, 1000, nil, nil, auth.NewRootUserNamespace())
			if f, err := vfsObj.OpenAt(ctx, userCreds, pop("/secret.txt"), &vfs.OpenOptions{Flags: linux.O_RDONLY}); !linuxerr.Equals(linuxerr.EACCES, err) {
				if f != nil {
					f.DecRef(ctx)
				}
				t.Fatalf("non-root OpenAt(0600) = %v, want EACCES", err)
			}
		}

		// Stalled RPC must unblock immediately with ERESTARTSYS when Sentry context is interrupted.
		entered := make(chan struct{}, 1)
		client.mu.Lock()
		client.beforeCall = func(rpcCtx goContext.Context, op string) error {
			if op == "stat" {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-rpcCtx.Done()
				return linuxerr.EINTR
			}
			return nil
		}
		client.mu.Unlock()

		ic := newInterruptibleCtx()
		statErrCh := make(chan error, 1)
		go func() {
			_, err := vfsObj.StatAt(ic, rootCreds, pop("/stalled.txt"), &vfs.StatOptions{})
			statErrCh <- err
		}()
		select {
		case <-entered:
		case err := <-statErrCh:
			t.Fatalf("StatAt returned %v before entering RPC hook", err)
		case <-time.After(3 * time.Second):
			t.Fatal("StatAt did not enter RPC hook")
		}
		ic.Interrupt()
		select {
		case err := <-statErrCh:
			if !linuxerr.Equals(linuxerr.ERESTARTSYS, err) {
				t.Fatalf("interrupted StatAt err = %v, want ERESTARTSYS", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("interrupted StatAt did not unblock")
		}
	})
}

type chunkedWatchClient struct {
	*localRootClient
	maxChunk int64

	wmu           sync.Mutex
	maxWatches    int
	watched       map[string]struct{}
	unwatchedCh   chan string
	notifyHandler func(NotifyEvent)
}

func (c *chunkedWatchClient) MaxChunkBytes() int64 { return c.maxChunk }

func (c *chunkedWatchClient) Watch(_ goContext.Context, relPath string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.watched == nil {
		c.watched = make(map[string]struct{})
	}
	if _, ok := c.watched[relPath]; ok {
		return nil
	}
	if c.maxWatches > 0 && len(c.watched) >= c.maxWatches {
		return linuxerr.ENOSPC
	}
	c.watched[relPath] = struct{}{}
	return nil
}

func (c *chunkedWatchClient) Unwatch(_ goContext.Context, relPath string) error {
	c.wmu.Lock()
	delete(c.watched, relPath)
	ch := c.unwatchedCh
	c.wmu.Unlock()
	if ch != nil {
		select {
		case ch <- relPath:
		default:
		}
	}
	return nil
}

func (c *chunkedWatchClient) SetNotifyHandler(fn func(NotifyEvent)) {
	c.wmu.Lock()
	c.notifyHandler = fn
	c.wmu.Unlock()
}

func (c *chunkedWatchClient) emit(ev NotifyEvent) {
	c.wmu.Lock()
	fn := c.notifyHandler
	c.wmu.Unlock()
	if fn != nil {
		fn(ev)
	}
}

func TestRPCFSReadReturnsIOEOFAtAndBeyondEOF(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := &chunkedWatchClient{
		localRootClient: &localRootClient{root: root},
		maxChunk:        16 << 10,
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })

	fs, rootD, err := NewFilesystem(ctx, &vfsObj, client, "chunked", false)
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{})
	fs.DecRef(ctx)
	rootVD := vfs.MakeVirtualDentry(mnt, rootD)
	t.Cleanup(func() { rootVD.DecRef(ctx) })

	payload := bytes.Repeat([]byte("0123456789abcdef"), 6000) // 96,000 bytes (not a chunk multiple)
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.bin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse(p)}
	}

	// Simulate sendfile(2): loop Read with a large buffer until io.EOF.
	fd, err := vfsObj.OpenAt(ctx, creds, pop("/blob.bin"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt blob.bin: %v", err)
	}
	defer fd.DecRef(ctx)

	var got []byte
	buf := make([]byte, 128<<10)
	for range 32 {
		n, rErr := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if errors.Is(rErr, io.EOF) {
			break
		}
		if rErr != nil {
			t.Fatalf("Read unexpected err: %v", rErr)
		}
		if n == 0 {
			t.Fatal("Read returned (0, nil) at EOF; must return io.EOF to avoid sendfile infinite loop")
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes, want %d bytes", len(got), len(payload))
	}

	// PRead at and beyond EOF must return (0, io.EOF).
	for _, off := range []int64{int64(len(payload)), int64(len(payload)) + 4096} {
		n, rErr := fd.PRead(ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{})
		if n != 0 || !errors.Is(rErr, io.EOF) {
			t.Fatalf("PRead(off=%d) = (%d, %v), want (0, io.EOF)", off, n, rErr)
		}
	}

	// Empty file must return (0, io.EOF) on first Read.
	efd, err := vfsObj.OpenAt(ctx, creds, pop("/empty.bin"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt empty.bin: %v", err)
	}
	defer efd.DecRef(ctx)
	if n, rErr := efd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); n != 0 || !errors.Is(rErr, io.EOF) {
		t.Fatalf("Read empty.bin = (%d, %v), want (0, io.EOF)", n, rErr)
	}
}

type singleFileLocalClient struct {
	*localRootClient
	leaf string
}

func (c *singleFileLocalClient) resolve(rel string) (string, error) {
	if rel != "." {
		return "", linuxerr.ENOTDIR
	}
	return c.leaf, nil
}

func (c *singleFileLocalClient) Stat(ctx goContext.Context, rel string) (Entry, error) {
	p, err := c.resolve(rel)
	if err != nil {
		return Entry{}, err
	}
	e, err := c.localRootClient.Stat(ctx, p)
	if err != nil {
		return Entry{}, err
	}
	e.Ino = 1
	e.Name = ""
	return e, nil
}

func (c *singleFileLocalClient) Read(ctx goContext.Context, rel string, offset, length int64) ([]byte, error) {
	p, err := c.resolve(rel)
	if err != nil {
		return nil, err
	}
	return c.localRootClient.Read(ctx, p, offset, length)
}

func (c *singleFileLocalClient) Write(ctx goContext.Context, rel string, offset int64, data []byte) (int64, error) {
	p, err := c.resolve(rel)
	if err != nil {
		return 0, err
	}
	return c.localRootClient.Write(ctx, p, offset, data)
}

func (c *singleFileLocalClient) Truncate(ctx goContext.Context, rel string, size int64) error {
	p, err := c.resolve(rel)
	if err != nil {
		return err
	}
	return c.localRootClient.Truncate(ctx, p, size)
}

func TestRPCFSSingleFileMount(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yml"), []byte("v: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := &singleFileLocalClient{
		localRootClient: &localRootClient{root: root},
		leaf:            "app.yml",
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })

	fs, rootD, err := NewFilesystemWithOptions(ctx, &vfsObj, client, Options{
		Label:      "app.yml",
		SingleFile: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{})
	fs.DecRef(ctx)
	rootVD := vfs.MakeVirtualDentry(mnt, rootD)
	t.Cleanup(func() { rootVD.DecRef(ctx) })

	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse(p)}
	}

	// Trailing slash "/" sets MustBeDir=true and must fail with ENOTDIR on a regular file.
	if _, err := vfsObj.StatAt(ctx, creds, pop("/"), &vfs.StatOptions{}); !linuxerr.Equals(linuxerr.ENOTDIR, err) {
		t.Fatalf("StatAt(/) = %v, want ENOTDIR", err)
	}

	st, err := vfsObj.StatAt(ctx, creds, pop(""), &vfs.StatOptions{})
	if err != nil {
		t.Fatalf("StatAt(\"\"): %v", err)
	}
	if st.Mode&linux.S_IFMT != linux.S_IFREG || st.Size != 5 {
		t.Fatalf("StatAt(\"\") = (mode=%#o, size=%d), want S_IFREG size 5", st.Mode, st.Size)
	}

	// O_CREAT|O_EXCL on existing single-file mount root must fail with EEXIST.
	if f, err := vfsObj.OpenAt(ctx, creds, pop(""), &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL}); !linuxerr.Equals(linuxerr.EEXIST, err) {
		if f != nil {
			f.DecRef(ctx)
		}
		t.Fatalf("OpenAt(O_CREAT|O_EXCL) = %v, want EEXIST", err)
	}
	// O_DIRECTORY and child lookups on single-file mount must return ENOTDIR.
	if f, err := vfsObj.OpenAt(ctx, creds, pop(""), &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY}); !linuxerr.Equals(linuxerr.ENOTDIR, err) {
		if f != nil {
			f.DecRef(ctx)
		}
		t.Fatalf("OpenAt(O_DIRECTORY) = %v, want ENOTDIR", err)
	}
	if _, err := vfsObj.StatAt(ctx, creds, pop("/sibling"), &vfs.StatOptions{}); !linuxerr.Equals(linuxerr.ENOTDIR, err) {
		t.Fatalf("StatAt(/sibling) = %v, want ENOTDIR", err)
	}

	fd, err := vfsObj.OpenAt(ctx, creds, pop(""), &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_TRUNC})
	if err != nil {
		t.Fatalf("OpenAt(O_RDWR|O_TRUNC): %v", err)
	}
	if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte("v: 2\n")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := fd.Seek(ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	buf := make([]byte, 16)
	n, err := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	fd.DecRef(ctx)
	if err != nil || string(buf[:n]) != "v: 2\n" {
		t.Fatalf("Read = (%q, %v), want v: 2", buf[:n], err)
	}
}

type inotifyIDCtx struct {
	gvcontext.Context
	mu     sync.Mutex
	nextID uint64
	cookie uint32
}

func (c *inotifyIDCtx) Value(key any) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch key {
	case uniqueid.CtxGlobalUniqueID:
		c.nextID++
		return c.nextID
	case uniqueid.CtxInotifyCookie:
		c.cookie++
		return c.cookie
	}
	return c.Context.Value(key)
}

func readOneInotifyEvent(t *testing.T, ctx gvcontext.Context, inFD *vfs.FileDescription) (wd int32, mask, cookie uint32, name string) {
	t.Helper()
	buf := make([]byte, 512)
	n, err := inFD.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || n < 16 {
		t.Fatalf("inFD.Read = (%d, %v), want >= 16 bytes", n, err)
	}
	wd = int32(binary.LittleEndian.Uint32(buf[0:4]))
	mask = binary.LittleEndian.Uint32(buf[4:8])
	cookie = binary.LittleEndian.Uint32(buf[8:12])
	nameLen := binary.LittleEndian.Uint32(buf[12:16])
	if nameLen > 0 {
		name = strings.TrimRight(string(buf[16:16+nameLen]), "\x00")
	}
	return wd, mask, cookie, name
}

func TestRPCFSWatchNotificationsAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "two.txt"), []byte("world\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	unwatchedCh := make(chan string, 4)
	client := &chunkedWatchClient{
		localRootClient: &localRootClient{root: root},
		maxChunk:        64 << 10,
		maxWatches:      2,
		unwatchedCh:     unwatchedCh,
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := &inotifyIDCtx{Context: gvcontext.Background()}
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })

	fs, rootD, err := NewFilesystem(ctx, &vfsObj, client, "watch-dir", false)
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{})
	fs.DecRef(ctx)
	rootVD := vfs.MakeVirtualDentry(mnt, rootD)
	t.Cleanup(func() { rootVD.DecRef(ctx) })

	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse(p)}
	}

	inFD, err := vfs.NewInotifyFD(ctx, &vfsObj, linux.O_NONBLOCK)
	if err != nil {
		t.Fatalf("NewInotifyFD: %v", err)
	}
	defer inFD.DecRef(ctx)
	ino := inFD.Impl().(*vfs.Inotify)

	oneVD, err := vfsObj.GetDentryAt(ctx, creds, pop("/one.txt"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(/one.txt): %v", err)
	}
	defer oneVD.DecRef(ctx)
	if err := oneVD.Dentry().Impl().(interface{ AdmitInotifyWatch() error }).AdmitInotifyWatch(); err != nil {
		t.Fatalf("AdmitInotifyWatch(/one.txt): %v", err)
	}
	oneWD := ino.AddWatch(oneVD.Dentry(), linux.IN_MODIFY|linux.IN_DELETE_SELF)

	dirVD, err := vfsObj.GetDentryAt(ctx, creds, pop("/"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(/): %v", err)
	}
	defer dirVD.DecRef(ctx)
	if err := dirVD.Dentry().Impl().(interface{ AdmitInotifyWatch() error }).AdmitInotifyWatch(); err != nil {
		t.Fatalf("AdmitInotifyWatch(/): %v", err)
	}
	dirWD := ino.AddWatch(dirVD.Dentry(), linux.IN_CREATE|linux.IN_DELETE)

	// Third distinct watched path must hit maxWatches=2 and return ENOSPC.
	twoVD, err := vfsObj.GetDentryAt(ctx, creds, pop("/two.txt"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(/two.txt): %v", err)
	}
	defer twoVD.DecRef(ctx)
	if err := twoVD.Dentry().Impl().(interface{ AdmitInotifyWatch() error }).AdmitInotifyWatch(); !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Fatalf("AdmitInotifyWatch(/two.txt) = %v, want ENOSPC", err)
	}

	// Host notification on one.txt reaches guest inotify fd.
	client.emit(NotifyEvent{Path: "one.txt", Mask: linux.IN_MODIFY})
	gotWD, gotMask, _, gotName := readOneInotifyEvent(t, ctx, inFD)
	if gotWD != oneWD || gotMask != linux.IN_MODIFY || gotName != "" {
		t.Fatalf("file notify = (wd=%d mask=%#x name=%q), want (wd=%d IN_MODIFY)", gotWD, gotMask, gotName, oneWD)
	}

	// Host notification on root directory reaches guest inotify fd with child name.
	client.emit(NotifyEvent{Path: ".", Name: "added.txt", Mask: linux.IN_CREATE})
	gotWD, gotMask, _, gotName = readOneInotifyEvent(t, ctx, inFD)
	if gotWD != dirWD || gotMask != linux.IN_CREATE || gotName != "added.txt" {
		t.Fatalf("dir notify = (wd=%d mask=%#x name=%q), want (wd=%d IN_CREATE added.txt)", gotWD, gotMask, gotName, dirWD)
	}

	// Removing watch triggers IN_IGNORED and async Unwatch on the client.
	if err := ino.RmWatch(ctx, oneWD); err != nil {
		t.Fatalf("RmWatch(oneWD): %v", err)
	}
	if ignWD, ignMask, _, _ := readOneInotifyEvent(t, ctx, inFD); ignWD != oneWD || ignMask != linux.IN_IGNORED {
		t.Fatalf("RmWatch event = (wd=%d mask=%#x), want (wd=%d IN_IGNORED)", ignWD, ignMask, oneWD)
	}
	select {
	case rel := <-unwatchedCh:
		if rel != "one.txt" {
			t.Fatalf("unwatched %q, want one.txt", rel)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Unwatch(one.txt)")
	}

	// Re-watching one.txt immediately after RmWatch must stay synced on the host.
	if err := oneVD.Dentry().Impl().(interface{ AdmitInotifyWatch() error }).AdmitInotifyWatch(); err != nil {
		t.Fatalf("re-AdmitInotifyWatch(/one.txt): %v", err)
	}
	reWD := ino.AddWatch(oneVD.Dentry(), linux.IN_MODIFY)
	client.emit(NotifyEvent{Path: "one.txt", Mask: linux.IN_MODIFY})
	gotWD, gotMask, _, _ = readOneInotifyEvent(t, ctx, inFD)
	if gotWD != reWD || gotMask != linux.IN_MODIFY {
		t.Fatalf("rewatched notify = (wd=%d mask=%#x), want (wd=%d IN_MODIFY)", gotWD, gotMask, reWD)
	}

	// Unlinking one.txt while an open FD holds a reference must detach its watch
	// so notifications for a recreated one.txt do not reach the dead dentry.
	openFD, err := vfsObj.OpenAt(ctx, creds, pop("/one.txt"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(/one.txt): %v", err)
	}
	defer openFD.DecRef(ctx)
	if err := vfsObj.UnlinkAt(ctx, creds, pop("/one.txt")); err != nil {
		t.Fatalf("UnlinkAt(/one.txt): %v", err)
	}
	select {
	case rel := <-unwatchedCh:
		if rel != "one.txt" {
			t.Fatalf("unwatched after unlink = %q, want one.txt", rel)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Unwatch(one.txt) after unlink with open FD")
	}
}
