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
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// Exported test types and constants for package hostfs_test.
type (
	TestEnv      = env
	CountingHost = countingHost
	TestClock    = testClock
)

const (
	PinIdleTimeForTest = pinIdleTime
	CacheTTLForTest    = cacheTTL
	MaxDirPinsForTest  = maxDirPins
)

var (
	NewCountEnvForTest   = newCountEnv
	WantErrnoForTest     = wantErrno
	HostFoldsCaseForTest = hostFoldsCase
	PathCallsForTest     = pathCalls
)

// countingHost wraps a host backend and counts every call that reaches it.
// The case flags override the answers of the wrapped backend when set.
type countingHost struct {
	hostBackend

	mu    sync.Mutex
	calls map[string]int
	// steps sums the path components of the path-based calls. Such a call
	// opens each parent directory in turn, so it costs about one host system
	// call per component. A pinned call costs one.
	steps int

	insensitive *bool
	verified    *bool
}

func (c *countingHost) count(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = make(map[string]int)
	}
	c.calls[name]++
}

// countPath counts a path-based call and the components that it walks.
func (c *countingHost) countPath(name string, rels ...string) {
	c.count(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rel := range rels {
		c.steps += len(strings.Split(rel, "/"))
	}
}

// reset forgets the calls so far.
func (c *countingHost) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
	c.steps = 0
}

// Reset forgets the calls so far.
func (c *countingHost) Reset() { c.reset() }

// syscalls estimates the host system calls of the counted calls: a pinned
// call makes one, and a path-based call makes one for each path component.
func (c *countingHost) syscalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.steps
	for name, v := range c.calls {
		if !pathCalls[name] {
			n += v
		}
	}
	return n
}

// listings counts the directory listings, by path and through a pinned handle.
func (c *countingHost) listings() int {
	return c.got("readDir") + c.got("readDirAt")
}

// Listings counts the directory listings, by path and through a pinned handle.
func (c *countingHost) Listings() int { return c.listings() }

// pathCalls names the counted calls that take a workspace path.
var pathCalls = map[string]bool{
	"open": true, "openDir": true, "lstat": true, "mkdir": true, "unlink": true,
	"rmdir": true, "rename": true, "link": true, "readlink": true, "readDir": true,
	"syncDir": true, "chtimes": true,
}

func (c *countingHost) got(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[name]
}

// Got returns the recorded call count for name.
func (c *countingHost) Got(name string) int { return c.got(name) }

func (c *countingHost) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.calls {
		n += v
	}
	return n
}

// Total returns the total recorded host calls.
func (c *countingHost) Total() int { return c.total() }

// dump lists the counted calls for a failure message.
func (c *countingHost) dump() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var parts []string
	for k, v := range c.calls {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, " ") + "]"
}

// Dump lists the counted calls for a failure message.
func (c *countingHost) Dump() string { return c.dump() }

// SetCaseFlags overrides the case-sensitivity and verification flags on c.
func (c *countingHost) SetCaseFlags(insensitive, verified bool) {
	c.insensitive = &insensitive
	c.verified = &verified
}

// CaseInsensitive reports whether the wrapped host backend is case-insensitive.
func (c *countingHost) CaseInsensitive() bool {
	return c.caseInsensitive()
}

func (c *countingHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	c.countPath("open", rel)
	return c.hostBackend.open(rel, flags, perm)
}

func (c *countingHost) openDir(rel string) (*os.File, error) {
	c.countPath("openDir", rel)
	return c.hostBackend.openDir(rel)
}

func (c *countingHost) lstat(rel string) (hostInfo, error) {
	c.countPath("lstat", rel)
	return c.hostBackend.lstat(rel)
}

func (c *countingHost) fstat(f *os.File) (hostInfo, error) {
	c.count("fstat")
	return c.hostBackend.fstat(f)
}

func (c *countingHost) mkdir(rel string) error {
	c.countPath("mkdir", rel)
	return c.hostBackend.mkdir(rel)
}

func (c *countingHost) unlink(rel string) error {
	c.countPath("unlink", rel)
	return c.hostBackend.unlink(rel)
}

func (c *countingHost) rmdir(rel string) error {
	c.countPath("rmdir", rel)
	return c.hostBackend.rmdir(rel)
}

func (c *countingHost) rename(oldRel, newRel string) error {
	c.countPath("rename", oldRel, newRel)
	return c.hostBackend.rename(oldRel, newRel)
}

func (c *countingHost) link(oldRel, newRel string) error {
	c.countPath("link", oldRel, newRel)
	return c.hostBackend.link(oldRel, newRel)
}

func (c *countingHost) readlink(rel string) (string, error) {
	c.countPath("readlink", rel)
	return c.hostBackend.readlink(rel)
}

func (c *countingHost) readDir(rel string) ([]hostDirEntry, error) {
	c.countPath("readDir", rel)
	return c.hostBackend.readDir(rel)
}

func (c *countingHost) syncDir(rel string) error {
	c.countPath("syncDir", rel)
	return c.hostBackend.syncDir(rel)
}

func (c *countingHost) chtimes(rel string, atime, mtime *time.Time) error {
	c.countPath("chtimes", rel)
	return c.hostBackend.chtimes(rel, atime, mtime)
}

func (c *countingHost) caseInsensitive() bool {
	if c.insensitive != nil {
		return *c.insensitive
	}
	return c.hostBackend.caseInsensitive()
}

func (c *countingHost) caseVerified() bool {
	if c.verified != nil {
		return *c.verified
	}
	return c.hostBackend.caseVerified()
}

func (c *countingHost) openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error) {
	c.count("openDirAt")
	return c.hostBackend.openDirAt(dir, name)
}

func (c *countingHost) closeDir(dir hostDirHandle) error {
	c.count("closeDir")
	return c.hostBackend.closeDir(dir)
}

func (c *countingHost) fstatDir(dir hostDirHandle) (hostInfo, error) {
	c.count("fstatDir")
	return c.hostBackend.fstatDir(dir)
}

func (c *countingHost) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	c.count("lstatAt")
	return c.hostBackend.lstatAt(dir, name)
}

func (c *countingHost) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	c.count("openChildAt")
	return c.hostBackend.openChildAt(dir, name, flags, perm)
}

func (c *countingHost) mkdirAt(dir hostDirHandle, name string) error {
	c.count("mkdirAt")
	return c.hostBackend.mkdirAt(dir, name)
}

func (c *countingHost) unlinkAt(dir hostDirHandle, name string) error {
	c.count("unlinkAt")
	return c.hostBackend.unlinkAt(dir, name)
}

func (c *countingHost) rmdirAt(dir hostDirHandle, name string) error {
	c.count("rmdirAt")
	return c.hostBackend.rmdirAt(dir, name)
}

func (c *countingHost) renameAt(oldDir hostDirHandle, oldName string, newDir hostDirHandle, newName string) error {
	c.count("renameAt")
	return c.hostBackend.renameAt(oldDir, oldName, newDir, newName)
}

func (c *countingHost) linkAt(oldDir hostDirHandle, oldName string, newDir hostDirHandle, newName string) error {
	c.count("linkAt")
	return c.hostBackend.linkAt(oldDir, oldName, newDir, newName)
}

func (c *countingHost) chtimesAt(dir hostDirHandle, name string, atime, mtime *time.Time) error {
	c.count("chtimesAt")
	return c.hostBackend.chtimesAt(dir, name, atime, mtime)
}

func (c *countingHost) readDirAt(dir hostDirHandle) ([]hostDirEntry, error) {
	c.count("readDirAt")
	return c.hostBackend.readDirAt(dir)
}

func (c *countingHost) syncDirAt(dir hostDirHandle) error {
	c.count("syncDirAt")
	return c.hostBackend.syncDirAt(dir)
}

// testClock is the monotonic clock of the cache expiry in tests.
type testClock struct {
	ns atomic.Int64
}

func (c *testClock) now() int64 {
	return c.ns.Load()
}

func (c *testClock) advance(d time.Duration) {
	c.ns.Add(int64(d))
}

// Advance moves the synthetic monotonic clock forward by d.
func (c *testClock) Advance(d time.Duration) {
	c.advance(d)
}

// newCountEnv mounts a workspace whose host backend counts calls and whose
// clock only moves when the test advances it.
func newCountEnv(t *testing.T) (*env, *countingHost, *testClock) {
	t.Helper()
	ch := &countingHost{}
	clock := &testClock{}
	clock.ns.Store(int64(time.Hour))
	e := newEnvOpts(t, workspaceOptions{
		coalesce: defaultCoalesceWindow,
		clock:    clock.now,
		wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		},
	})
	return e, ch, clock
}

// pinCount reports the number of pinned directory handles.
func (w *Workspace) pinCount() int {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	return len(w.pins)
}

// Exported VFS helper methods on *env for package hostfs_test.

func (e *env) Ctx() gvcontext.Context       { return e.ctx }
func (e *env) Dir() string                  { return e.dir }
func (e *env) Workspace() *Workspace        { return e.ws }
func (e *env) Host(p string) string         { return e.host(p) }
func (e *env) Mkdir(p string) error         { return e.mkdir(p) }
func (e *env) MustMkdir(p string)           { e.mustMkdir(p) }
func (e *env) WriteFile(p string, b []byte) { e.writeFile(p, b) }
func (e *env) ReadFile(p string) []byte     { return e.readFile(p) }
func (e *env) ReadAll(fd *vfs.FileDescription) []byte {
	return e.readAll(fd)
}
func (e *env) Open(p string, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return e.open(p, flags, mode)
}
func (e *env) MustOpen(p string, flags uint32) *vfs.FileDescription {
	return e.mustOpen(p, flags)
}
func (e *env) Stat(p string) (linux.Statx, error) { return e.stat(p) }
func (e *env) MustStat(p string) linux.Statx      { return e.mustStat(p) }
func (e *env) Unlink(p string) error              { return e.unlink(p) }
func (e *env) Rename(oldPath, newPath string) error {
	return e.rename(oldPath, newPath)
}
func (e *env) Link(oldPath, newPath string) error {
	return e.link(oldPath, newPath)
}
func (e *env) Readdir(p string) []string { return e.readdir(p) }
func (e *env) SetStat(p string, stat linux.Statx) error {
	return e.setStat(p, stat)
}
func (e *env) Mknod(p string, mode linux.FileMode) error {
	return e.vfsObj.MknodAt(e.ctx, e.creds, e.pop(p), &vfs.MknodOptions{Mode: mode})
}
func (e *env) Symlink(p, target string) error {
	return e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop(p), target)
}
func (e *env) Rmdir(p string) error {
	return e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop(p))
}
func (e *env) PinCount() int { return e.ws.pinCount() }
func (e *env) SweepPins()    { e.ws.sweepPins() }
func (e *env) CloseWorkspace() error {
	return e.ws.Close()
}
