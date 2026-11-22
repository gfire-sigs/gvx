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
	goContext "context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

type localRootClient struct {
	mu     sync.Mutex
	root   *os.Root
	closed bool
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
	}
}

func (c *localRootClient) checkOpen() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return linuxerr.EIO
	}
	return nil
}

func (c *localRootClient) Stat(_ goContext.Context, rel string) (Entry, error) {
	if err := c.checkOpen(); err != nil {
		return Entry{}, err
	}
	fi, err := c.root.Lstat(rel)
	if err != nil {
		return Entry{}, c.mapErr(err)
	}
	return c.entryFromInfo(filepath.Base(rel), fi), nil
}

func (c *localRootClient) Readdir(_ goContext.Context, rel string) ([]Entry, error) {
	if err := c.checkOpen(); err != nil {
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

func (c *localRootClient) Read(_ goContext.Context, rel string, offset, length int64) ([]byte, error) {
	if err := c.checkOpen(); err != nil {
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

func (c *localRootClient) Write(_ goContext.Context, rel string, offset int64, data []byte) (int64, error) {
	if err := c.checkOpen(); err != nil {
		return 0, err
	}
	f, err := c.root.OpenFile(rel, os.O_WRONLY, 0)
	if err != nil {
		return 0, c.mapErr(err)
	}
	defer f.Close()
	n, err := f.WriteAt(data, offset)
	return int64(n), c.mapErr(err)
}

func (c *localRootClient) Create(_ goContext.Context, rel string, mode, _ uint32) (Entry, error) {
	if err := c.checkOpen(); err != nil {
		return Entry{}, err
	}
	f, err := c.root.OpenFile(rel, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(mode))
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

func (c *localRootClient) Mkdir(_ goContext.Context, rel string, mode uint32) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.mapErr(c.root.Mkdir(rel, os.FileMode(mode)))
}

func (c *localRootClient) Unlink(_ goContext.Context, rel string) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.mapErr(c.root.Remove(rel))
}

func (c *localRootClient) Rmdir(_ goContext.Context, rel string) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.mapErr(c.root.Remove(rel))
}

func (c *localRootClient) Rename(_ goContext.Context, oldRel, newRel string) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.mapErr(c.root.Rename(oldRel, newRel))
}

func (c *localRootClient) Truncate(_ goContext.Context, rel string, size int64) error {
	if err := c.checkOpen(); err != nil {
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

func (c *localRootClient) Chmod(_ goContext.Context, rel string, mode uint32) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.mapErr(c.root.Chmod(rel, os.FileMode(mode)))
}

func (c *localRootClient) Utimens(goContext.Context, string, int64, int64, bool, bool) error {
	return c.checkOpen()
}

func (c *localRootClient) Readlink(_ goContext.Context, rel string) (string, error) {
	if err := c.checkOpen(); err != nil {
		return "", err
	}
	t, err := c.root.Readlink(rel)
	return t, c.mapErr(err)
}

func (c *localRootClient) Symlink(_ goContext.Context, target, linkRel string) error {
	if err := c.checkOpen(); err != nil {
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

func TestRPCFSReadWriteAndDisconnectEIO(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	client := &localRootClient{root: root}

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	defer vfsObj.Release(ctx)

	fs, rootD, err := NewFilesystem(ctx, &vfsObj, client, "host-dir")
	if err != nil {
		t.Fatal(err)
	}
	mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{})
	fs.DecRef(ctx)
	rootVD := vfs.MakeVirtualDentry(mnt, rootD)
	defer rootVD.DecRef(ctx)

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

	// Disconnecting the backing client must yield EIO cleanly without panicking.
	_ = client.Close()
	if _, err := vfsObj.StatAt(ctx, creds, pop("/sub/hello.txt"), &vfs.StatOptions{}); err != linuxerr.EIO {
		t.Fatalf("StatAt after client disconnect = %v, want EIO", err)
	}
}
