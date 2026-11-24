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
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/rpcfs"
)

// ServeMount configures an rpcfs mount reattached during Restore.
// When Client is non-nil, Restore attaches Client directly without opening any
// host path. Restore takes ownership of Client once CompleteRestore attaches
// it and closes it when the sandbox closes or unmounts; if Restore fails before
// CompleteRestore attaches Client, the caller retains ownership. When Client is
// nil, HostPath must refer to a host directory or regular file that Restore
// opens via hostfs.Workspace before host lockdown.
type ServeMount struct {
	HostPath   string
	GuestPath  string
	ReadOnly   bool
	SingleFile bool
	Client     rpcfs.Client
}

// ParseServeMount parses a HOST_PATH:GUEST_PATH[:ro|rw] serve mount spec.
func ParseServeMount(spec string) (ServeMount, error) {
	return parseHostGuestMountSpec(spec, "serve mount")
}

func parseHostGuestMountSpec(spec, label string) (ServeMount, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return ServeMount{}, fmt.Errorf("%w: empty %s specification (want HOST_PATH:GUEST_PATH[:ro|rw])", ErrInvalidConfig, label)
	}
	hostPath, guestPath, mode, err := splitVolumeSpec(s)
	if err != nil {
		return ServeMount{}, fmt.Errorf("%w: invalid %s %q (want HOST_PATH:GUEST_PATH[:ro|rw])", ErrInvalidConfig, label, spec)
	}
	hostPath = strings.TrimSpace(hostPath)
	guestPath = strings.TrimSpace(guestPath)
	if hostPath == "" || guestPath == "" {
		return ServeMount{}, fmt.Errorf("%w: invalid %s %q (want HOST_PATH:GUEST_PATH[:ro|rw])", ErrInvalidConfig, label, spec)
	}
	var ro bool
	if mode != "" {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "ro", "readonly":
			ro = true
		case "rw":
			ro = false
		default:
			return ServeMount{}, fmt.Errorf("%w: unsupported %s option %q (want ro or rw)", ErrInvalidConfig, label, mode)
		}
	}
	return ServeMount{
		HostPath:  hostPath,
		GuestPath: guestPath,
		ReadOnly:  ro,
	}, nil
}

type sandboxServeMount struct {
	ServeMount
	hostPath    string
	localClient rpcfs.Client
}

// openLocalRPCFSClient opens hostPath via hostfs.Workspace before host lockdown
// so all operations route through the OS lockdown containment layer (Windows
// ActiveWindowsFileBroker, Linux openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS,
// and macOS Seatbelt with single-file pinning).
func openLocalRPCFSClient(hostPath string, readOnly bool) (client rpcfs.Client, absHost string, singleFile bool, err error) {
	abs, err := filepath.Abs(hostPath)
	if err != nil {
		return nil, "", false, fmt.Errorf("gvx: resolve serve mount %q: %w", hostPath, err)
	}
	kind, err := classifyHostPath(abs)
	if err != nil {
		return nil, "", false, fmt.Errorf("%w: serve mount %q: %w", ErrInvalidConfig, abs, err)
	}
	if kind == hostPathMissing {
		return nil, "", false, fmt.Errorf("gvx: serve mount %q does not exist", abs)
	}
	if kind == hostPathFile {
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, "", false, fmt.Errorf("gvx: resolve serve file %q: %w", abs, err)
		}
		abs = resolved
	}
	ws, err := hostfs.OpenWorkspace(abs, readOnly)
	if err != nil {
		return nil, "", false, fmt.Errorf("gvx: open serve mount %q: %w", abs, err)
	}
	return &localRPCFSClient{
		ws:         ws,
		singleFile: ws.SingleFile(),
		readOnly:   ws.ReadOnly(),
	}, ws.HostPath(), ws.SingleFile(), nil
}

// localRPCFSClient implements rpcfs.Client backed by a pre-opened
// hostfs.Workspace.
type localRPCFSClient struct {
	ws         *hostfs.Workspace
	singleFile bool
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
	return c.ws.Close()
}

func (c *localRPCFSClient) resolveRel(raw string, op string) (string, error) {
	if strings.ContainsRune(raw, 0) {
		return "", linuxerr.EINVAL
	}
	norm := strings.ReplaceAll(raw, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", linuxerr.EINVAL
		}
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+norm), "/")
	if cleaned == "" {
		cleaned = "."
	}
	if !c.singleFile {
		return cleaned, nil
	}
	if cleaned != "." {
		return "", linuxerr.ENOTDIR
	}
	switch op {
	case "readdir", "create", "mkdir", "symlink":
		return "", linuxerr.ENOTDIR
	case "unlink", "rmdir", "rename":
		return "", linuxerr.EBUSY
	case "readlink":
		return "", linuxerr.EINVAL
	}
	return ".", nil
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

func (c *localRPCFSClient) entryFromAttr(rel, name string, attr hostfs.POSIXAttr, size int64) rpcfs.Entry {
	nlink := uint32(1)
	if attr.Mode&linux.S_IFMT == linux.S_IFDIR {
		nlink = 2
	}
	ino := localStableIno(rel)
	if c.singleFile {
		ino = 1
		name = ""
	}
	return rpcfs.Entry{
		Name:       name,
		Ino:        ino,
		Mode:       attr.Mode,
		Size:       size,
		Nlink:      nlink,
		UID:        attr.UID,
		GID:        attr.GID,
		AtimeNS:    attr.Atime,
		MtimeNS:    attr.Mtime,
		CtimeNS:    attr.Ctime,
		LinkTarget: attr.Symlink,
	}
}

func (c *localRPCFSClient) Stat(_ context.Context, relPath string) (rpcfs.Entry, error) {
	rel, err := c.resolveRel(relPath, "stat")
	if err != nil {
		return rpcfs.Entry{}, err
	}
	attr, size, err := c.ws.Stat(rel)
	if err != nil {
		return rpcfs.Entry{}, hostfs.TranslateError(err)
	}
	return c.entryFromAttr(rel, path.Base(rel), attr, size), nil
}

func (c *localRPCFSClient) Readdir(_ context.Context, relPath string) ([]rpcfs.Entry, error) {
	rel, err := c.resolveRel(relPath, "readdir")
	if err != nil {
		return nil, err
	}
	children, err := c.ws.ReadDirChildren(rel)
	if err != nil {
		return nil, hostfs.TranslateError(err)
	}
	out := make([]rpcfs.Entry, 0, len(children))
	for _, ch := range children {
		childRel := ch.Name
		if rel != "." {
			childRel = rel + "/" + ch.Name
		}
		out = append(out, c.entryFromAttr(childRel, ch.Name, ch.Attr, ch.Size))
	}
	return out, nil
}

func (c *localRPCFSClient) Read(_ context.Context, relPath string, offset, length int64) ([]byte, error) {
	rel, err := c.resolveRel(relPath, "read")
	if err != nil {
		return nil, err
	}
	if offset < 0 || length < 0 {
		return nil, linuxerr.EINVAL
	}
	if length == 0 {
		return nil, nil
	}
	f, err := c.ws.OpenFile(rel, os.O_RDONLY, 0)
	if err != nil {
		return nil, hostfs.TranslateError(err)
	}
	defer f.Close()
	buf := make([]byte, min(length, c.MaxChunkBytes()))
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, hostfs.TranslateError(err)
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
	rel, err := c.resolveRel(relPath, "write")
	if err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	f, err := c.ws.OpenFile(rel, os.O_WRONLY, 0)
	if err != nil {
		return 0, hostfs.TranslateError(err)
	}
	n, err := f.WriteAt(data, offset)
	closeErr := f.Close()
	if err != nil {
		return int64(n), hostfs.TranslateError(err)
	}
	if closeErr != nil {
		return int64(n), hostfs.TranslateError(closeErr)
	}
	return int64(n), nil
}

func (c *localRPCFSClient) Create(_ context.Context, relPath string, mode, flags uint32) (rpcfs.Entry, error) {
	if c.readOnly {
		return rpcfs.Entry{}, linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "create")
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
	perm := mode & 0o777
	if perm == 0 {
		perm = 0o644
	}
	f, err := c.ws.OpenFile(rel, osFlags, perm)
	if err != nil {
		return rpcfs.Entry{}, hostfs.TranslateError(err)
	}
	_ = f.Close()
	attr, size, err := c.ws.Stat(rel)
	if err != nil {
		return rpcfs.Entry{}, hostfs.TranslateError(err)
	}
	return c.entryFromAttr(rel, path.Base(rel), attr, size), nil
}

func (c *localRPCFSClient) Mkdir(_ context.Context, relPath string, mode uint32) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "mkdir")
	if err != nil {
		return err
	}
	perm := mode & 0o777
	if perm == 0 {
		perm = 0o755
	}
	return hostfs.TranslateError(c.ws.Mkdir(rel, perm))
}

func (c *localRPCFSClient) Unlink(_ context.Context, relPath string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "unlink")
	if err != nil {
		return err
	}
	return hostfs.TranslateError(c.ws.Unlink(rel))
}

func (c *localRPCFSClient) Rmdir(_ context.Context, relPath string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "rmdir")
	if err != nil {
		return err
	}
	return hostfs.TranslateError(c.ws.Rmdir(rel))
}

func (c *localRPCFSClient) Rename(_ context.Context, oldRel, newRel string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	oldClean, err := c.resolveRel(oldRel, "rename")
	if err != nil {
		return err
	}
	newClean, err := c.resolveRel(newRel, "rename")
	if err != nil {
		return err
	}
	return hostfs.TranslateError(c.ws.Rename(oldClean, newClean))
}

func (c *localRPCFSClient) Truncate(_ context.Context, relPath string, size int64) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "truncate")
	if err != nil {
		return err
	}
	if size < 0 {
		return linuxerr.EINVAL
	}
	return hostfs.TranslateError(c.ws.Truncate(rel, size))
}

func (c *localRPCFSClient) Chmod(_ context.Context, relPath string, mode uint32) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "chmod")
	if err != nil {
		return err
	}
	return hostfs.TranslateError(c.ws.Chmod(rel, mode&0o7777))
}

func (c *localRPCFSClient) Utimens(_ context.Context, relPath string, atimeNS, mtimeNS int64, setAtime, setMtime bool) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(relPath, "utimens")
	if err != nil {
		return err
	}
	var atime, mtime *time.Time
	if setAtime {
		t := time.Unix(0, atimeNS)
		atime = &t
	}
	if setMtime {
		t := time.Unix(0, mtimeNS)
		mtime = &t
	}
	return hostfs.TranslateError(c.ws.Chtimes(rel, atime, mtime))
}

func (c *localRPCFSClient) Readlink(_ context.Context, relPath string) (string, error) {
	rel, err := c.resolveRel(relPath, "readlink")
	if err != nil {
		return "", err
	}
	target, err := c.ws.Readlink(rel)
	if err != nil {
		return "", hostfs.TranslateError(err)
	}
	return target, nil
}

func (c *localRPCFSClient) Symlink(_ context.Context, target, linkRel string) error {
	if c.readOnly {
		return linuxerr.EROFS
	}
	rel, err := c.resolveRel(linkRel, "symlink")
	if err != nil {
		return err
	}
	if err := validateLocalSymlinkTarget(rel, target); err != nil {
		return err
	}
	return hostfs.TranslateError(c.ws.Symlink(target, rel))
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
