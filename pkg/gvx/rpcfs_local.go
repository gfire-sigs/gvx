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
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/rpcfs"
)

// ServeMount configures an rpcfs mount reattached during Restore.
// When Client is non-nil, Restore attaches Client directly without opening any
// host path. When Client is nil, HostPath must refer to a host directory or
// regular file that Restore opens via os.OpenRoot before host lockdown.
type ServeMount struct {
	HostPath   string
	GuestPath  string
	ReadOnly   bool
	SingleFile bool
	Client     rpcfs.Client
}

// ParseServeMount parses a HOST_PATH:GUEST_PATH[:ro|rw] serve mount spec.
func ParseServeMount(spec string) (ServeMount, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return ServeMount{}, fmt.Errorf("%w: empty serve mount specification (want HOST_PATH:GUEST_PATH[:ro|rw])", ErrInvalidConfig)
	}
	parts := splitMountSpec(s)
	if len(parts) < 2 || len(parts) > 3 {
		return ServeMount{}, fmt.Errorf("%w: invalid serve mount %q (want HOST_PATH:GUEST_PATH[:ro|rw])", ErrInvalidConfig, spec)
	}
	hostPath := strings.TrimSpace(parts[0])
	guestPath := strings.TrimSpace(parts[1])
	if hostPath == "" || guestPath == "" {
		return ServeMount{}, fmt.Errorf("%w: invalid serve mount %q (want HOST_PATH:GUEST_PATH[:ro|rw])", ErrInvalidConfig, spec)
	}
	var ro bool
	if len(parts) == 3 {
		switch strings.ToLower(strings.TrimSpace(parts[2])) {
		case "ro", "readonly":
			ro = true
		case "rw":
			ro = false
		default:
			return ServeMount{}, fmt.Errorf("%w: unsupported serve mount option %q (want ro or rw)", ErrInvalidConfig, parts[2])
		}
	}
	return ServeMount{
		HostPath:  hostPath,
		GuestPath: guestPath,
		ReadOnly:  ro,
	}, nil
}

// splitMountSpec splits HOST:GUEST[:OPT] while preserving a leading Windows
// drive prefix such as "C:\dir".
func splitMountSpec(s string) []string {
	start := 0
	if len(s) >= 2 && s[1] == ':' && ((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		start = 2
	}
	rest := strings.Split(s[start:], ":")
	rest[0] = s[:start] + rest[0]
	return rest
}

type sandboxServeMount struct {
	ServeMount
	hostPath    string
	localClient rpcfs.Client
}

// openLocalRPCFSClient opens hostPath via os.OpenRoot before host lockdown and
// returns an in-process rpcfs.Client backed by that pinned root.
func openLocalRPCFSClient(hostPath string, readOnly bool) (client rpcfs.Client, absHost string, singleFile bool, err error) {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return nil, "", false, fmt.Errorf("gvx: resolve serve mount %q: %w", hostPath, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, "", false, fmt.Errorf("gvx: stat serve mount %q: %w", abs, err)
	}
	if fi.IsDir() {
		root, err := os.OpenRoot(abs)
		if err != nil {
			return nil, "", false, fmt.Errorf("gvx: open serve directory %q: %w", abs, err)
		}
		return &localRPCFSClient{
			root:     root,
			readOnly: readOnly,
		}, abs, false, nil
	}
	if !fi.Mode().IsRegular() {
		return nil, "", false, fmt.Errorf("%w: serve mount %q must be a directory or regular file", ErrInvalidConfig, abs)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, "", false, fmt.Errorf("gvx: resolve serve file %q: %w", abs, err)
	}
	root, err := os.OpenRoot(filepath.Dir(resolved))
	if err != nil {
		return nil, "", false, fmt.Errorf("gvx: open serve file parent %q: %w", filepath.Dir(resolved), err)
	}
	return &localRPCFSClient{
		root:       root,
		singleFile: true,
		leafName:   filepath.Base(resolved),
		readOnly:   readOnly,
	}, resolved, true, nil
}

// localRPCFSClient implements rpcfs.Client directly on a pre-opened *os.Root.
type localRPCFSClient struct {
	root       *os.Root
	singleFile bool
	leafName   string
	readOnly   bool

	mu     sync.Mutex
	closed bool
}

func (c *localRPCFSClient) MaxChunkBytes() int64 { return 256 << 10 }

func (c *localRPCFSClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.root.Close()
}

func (c *localRPCFSClient) resolveRel(raw string, op string) (rel, hostRel string, err error) {
	if strings.ContainsRune(raw, 0) {
		return "", "", linuxerr.EINVAL
	}
	norm := strings.ReplaceAll(raw, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", "", linuxerr.EINVAL
		}
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+norm), "/")
	if cleaned == "" {
		cleaned = "."
	}
	if !c.singleFile {
		return cleaned, cleaned, nil
	}
	if cleaned != "." {
		return "", "", linuxerr.ENOTDIR
	}
	switch op {
	case "readdir", "create", "mkdir", "symlink":
		return "", "", linuxerr.ENOTDIR
	case "unlink", "rmdir", "rename":
		return "", "", linuxerr.EBUSY
	case "readlink":
		return "", "", linuxerr.EINVAL
	}
	return ".", c.leafName, nil
}

func (c *localRPCFSClient) hostErr(err error) error {
	if err == nil {
		return nil
	}
	return errnoToLinuxErr(control.HostErrorToLinuxErrno(err))
}

func localStableIno(rel string) uint64 {
	if rel == "." || rel == "" {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(rel))
	v := h.Sum64()
	if v <= 1 {
		return 2
	}
	return v
}

func localModeToLinux(m fs.FileMode) uint32 {
	perm := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		perm |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		perm |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		perm |= 0o1000
	}
	switch {
	case m.IsDir():
		return linux.S_IFDIR | perm
	case m&os.ModeSymlink != 0:
		return linux.S_IFLNK | perm
	default:
		return linux.S_IFREG | perm
	}
}

func (c *localRPCFSClient) entryFromInfo(rel, hostRel, name string, fi os.FileInfo) rpcfs.Entry {
	nlink := uint32(1)
	if fi.IsDir() {
		nlink = 2
	}
	var linkTarget string
	if !c.singleFile && fi.Mode()&os.ModeSymlink != 0 {
		if target, err := c.root.Readlink(hostRel); err == nil {
			linkTarget = target
		}
	}
	ino := localStableIno(rel)
	if c.singleFile {
		ino = 1
		name = ""
	}
	mtime := fi.ModTime().UnixNano()
	return rpcfs.Entry{
		Name:       name,
		Ino:        ino,
		Mode:       localModeToLinux(fi.Mode()),
		Size:       fi.Size(),
		Nlink:      nlink,
		AtimeNS:    mtime,
		MtimeNS:    mtime,
		CtimeNS:    mtime,
		LinkTarget: linkTarget,
	}
}

func (c *localRPCFSClient) checkRegular(hostRel string) error {
	fi, err := c.root.Lstat(hostRel)
	if err != nil {
		return c.hostErr(err)
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return linuxerr.ELOOP
	case fi.IsDir():
		return linuxerr.EISDIR
	case !fi.Mode().IsRegular():
		return linuxerr.EOPNOTSUPP
	default:
		return nil
	}
}

func (c *localRPCFSClient) Stat(_ context.Context, relPath string) (rpcfs.Entry, error) {
	rel, hostRel, err := c.resolveRel(relPath, "stat")
	if err != nil {
		return rpcfs.Entry{}, err
	}
	fi, err := c.root.Lstat(hostRel)
	if err != nil {
		return rpcfs.Entry{}, c.hostErr(err)
	}
	return c.entryFromInfo(rel, hostRel, path.Base(rel), fi), nil
}

func (c *localRPCFSClient) Readdir(_ context.Context, relPath string) ([]rpcfs.Entry, error) {
	rel, hostRel, err := c.resolveRel(relPath, "readdir")
	if err != nil {
		return nil, err
	}
	f, err := c.root.Open(hostRel)
	if err != nil {
		return nil, c.hostErr(err)
	}
	des, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return nil, c.hostErr(err)
	}
	slices.SortFunc(des, func(a, b os.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	out := make([]rpcfs.Entry, 0, len(des))
	for _, de := range des {
		childRel := de.Name()
		if rel != "." {
			childRel = rel + "/" + de.Name()
		}
		fi, err := c.root.Lstat(childRel)
		if err != nil {
			continue
		}
		out = append(out, c.entryFromInfo(childRel, childRel, de.Name(), fi))
	}
	return out, nil
}

func (c *localRPCFSClient) Read(_ context.Context, relPath string, offset, length int64) ([]byte, error) {
	_, hostRel, err := c.resolveRel(relPath, "read")
	if err != nil {
		return nil, err
	}
	if offset < 0 || length < 0 {
		return nil, linuxerr.EINVAL
	}
	if err := c.checkRegular(hostRel); err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	f, err := c.root.Open(hostRel)
	if err != nil {
		return nil, c.hostErr(err)
	}
	defer f.Close()
	buf := make([]byte, min(length, c.MaxChunkBytes()))
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, c.hostErr(err)
	}
	if n == 0 && errors.Is(err, io.EOF) {
		return nil, io.EOF
	}
	return buf[:n], nil
}

func (c *localRPCFSClient) Write(_ context.Context, relPath string, offset int64, data []byte) (int64, error) {
	if c.readOnly {
		return 0, linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "write")
	if err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	if err := c.checkRegular(hostRel); err != nil {
		return 0, err
	}
	f, err := c.root.OpenFile(hostRel, os.O_WRONLY, 0)
	if err != nil {
		return 0, c.hostErr(err)
	}
	n, err := f.WriteAt(data, offset)
	closeErr := f.Close()
	if err != nil {
		return int64(n), c.hostErr(err)
	}
	if closeErr != nil {
		return int64(n), c.hostErr(closeErr)
	}
	return int64(n), nil
}

func (c *localRPCFSClient) Create(_ context.Context, relPath string, mode, flags uint32) (rpcfs.Entry, error) {
	if c.readOnly {
		return rpcfs.Entry{}, linuxerr.EROFS
	}
	rel, hostRel, err := c.resolveRel(relPath, "create")
	if err != nil {
		return rpcfs.Entry{}, err
	}
	osFlags := os.O_RDWR | os.O_CREATE
	if flags&linux.O_EXCL != 0 {
		osFlags |= os.O_EXCL
	}
	if flags&linux.O_TRUNC != 0 {
		osFlags |= os.O_TRUNC
	}
	perm := os.FileMode(mode) & 0o777
	if perm == 0 {
		perm = 0o644
	}
	f, err := c.root.OpenFile(hostRel, osFlags, perm)
	if err != nil {
		return rpcfs.Entry{}, c.hostErr(err)
	}
	_ = f.Close()
	fi, err := c.root.Lstat(hostRel)
	if err != nil {
		return rpcfs.Entry{}, c.hostErr(err)
	}
	return c.entryFromInfo(rel, hostRel, path.Base(rel), fi), nil
}

func (c *localRPCFSClient) Mkdir(_ context.Context, relPath string, mode uint32) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "mkdir")
	if err != nil {
		return err
	}
	perm := os.FileMode(mode) & 0o777
	if perm == 0 {
		perm = 0o755
	}
	return c.hostErr(c.root.Mkdir(hostRel, perm))
}

func (c *localRPCFSClient) Unlink(_ context.Context, relPath string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "unlink")
	if err != nil {
		return err
	}
	return c.hostErr(c.root.Remove(hostRel))
}

func (c *localRPCFSClient) Rmdir(_ context.Context, relPath string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "rmdir")
	if err != nil {
		return err
	}
	return c.hostErr(c.root.Remove(hostRel))
}

func (c *localRPCFSClient) Rename(_ context.Context, oldRel, newRel string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, oldHost, err := c.resolveRel(oldRel, "rename")
	if err != nil {
		return err
	}
	_, newHost, err := c.resolveRel(newRel, "rename")
	if err != nil {
		return err
	}
	if err := verifyLocalSubtreeSymlinks(c.root, oldHost, newHost); err != nil {
		return err
	}
	return c.hostErr(c.root.Rename(oldHost, newHost))
}

func (c *localRPCFSClient) Truncate(_ context.Context, relPath string, size int64) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "truncate")
	if err != nil {
		return err
	}
	if size < 0 {
		return linuxerr.EINVAL
	}
	if err := c.checkRegular(hostRel); err != nil {
		return err
	}
	f, err := c.root.OpenFile(hostRel, os.O_WRONLY, 0)
	if err != nil {
		return c.hostErr(err)
	}
	tErr := f.Truncate(size)
	closeErr := f.Close()
	if tErr != nil {
		return c.hostErr(tErr)
	}
	return c.hostErr(closeErr)
}

func (c *localRPCFSClient) Chmod(_ context.Context, relPath string, mode uint32) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "chmod")
	if err != nil {
		return err
	}
	return c.hostErr(c.root.Chmod(hostRel, os.FileMode(mode)&0o777))
}

func (c *localRPCFSClient) Utimens(_ context.Context, relPath string, atimeNS, mtimeNS int64, setAtime, setMtime bool) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	_, hostRel, err := c.resolveRel(relPath, "utimens")
	if err != nil {
		return err
	}
	var atime, mtime time.Time
	if setAtime {
		atime = time.Unix(0, atimeNS)
	}
	if setMtime {
		mtime = time.Unix(0, mtimeNS)
	}
	return c.hostErr(c.root.Chtimes(hostRel, atime, mtime))
}

func (c *localRPCFSClient) Readlink(_ context.Context, relPath string) (string, error) {
	_, hostRel, err := c.resolveRel(relPath, "readlink")
	if err != nil {
		return "", err
	}
	target, err := c.root.Readlink(hostRel)
	if err != nil {
		return "", c.hostErr(err)
	}
	return target, nil
}

func (c *localRPCFSClient) Symlink(_ context.Context, target, linkRel string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, hostRel, err := c.resolveRel(linkRel, "symlink")
	if err != nil {
		return err
	}
	if err := validateLocalSymlinkTarget(rel, target); err != nil {
		return err
	}
	return c.hostErr(c.root.Symlink(target, hostRel))
}

func validateLocalSymlinkTarget(linkRel, target string) error {
	if target == "" || strings.ContainsRune(target, 0) || strings.HasPrefix(target, "/") || strings.Contains(target, `\`) {
		return linuxerr.EACCES
	}
	parent := path.Dir(linkRel)
	if parent == "." {
		parent = ""
	}
	depth := 0
	if parent != "" {
		depth = len(strings.Split(parent, "/"))
	}
	for _, seg := range strings.Split(target, "/") {
		switch seg {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return linuxerr.EACCES
			}
		default:
			depth++
		}
	}
	return nil
}

func verifyLocalSubtreeSymlinks(root *os.Root, srcRel, dstRel string) error {
	fi, err := root.Lstat(srcRel)
	if err != nil {
		return nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := root.Readlink(srcRel)
		if err != nil {
			return linuxerr.EACCES
		}
		return validateLocalSymlinkTarget(dstRel, target)
	}
	if !fi.IsDir() {
		return nil
	}
	f, err := root.Open(srcRel)
	if err != nil {
		return nil
	}
	des, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return nil
	}
	for _, de := range des {
		if err := verifyLocalSubtreeSymlinks(root, path.Join(srcRel, de.Name()), path.Join(dstRel, de.Name())); err != nil {
			return err
		}
	}
	return nil
}
