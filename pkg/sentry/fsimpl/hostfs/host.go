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
	"errors"
	"os"
	"time"
)

// This file defines the contract between the platform-neutral hostfs code and
// the per-platform host access layer. Each platform file set defines a
// hostRoot type with the methods of hostBackend, and these package functions:
//
//	func newHostRoot(root *os.Root) (*hostRoot, error)
//	func hostErrno(err error) (error, bool)
//
// Every path method takes a cleaned, slash-separated, workspace-relative path
// with no "." or ".." components ("." names the workspace root itself). No
// method may reach a file by absolute path or follow a symbolic link,
// junction, or mount point at any component.
//
// The pinned-directory methods take an open directory handle (hostDirHandle,
// declared by each platform file set) and one name without a separator. They
// resolve the name inside that directory only, so a lookup costs one host call
// at any depth. The caller of openDirAt owns the handle that it returns and
// releases it with closeDir. The handle of rootDir belongs to the backend.

// hostBackend is the host access layer that Workspace uses. hostRoot
// implements it. Tests wrap it to count host calls.
type hostBackend interface {
	close() error
	open(rel string, flags int, perm os.FileMode) (*os.File, error)
	openDir(rel string) (*os.File, error)
	lstat(rel string) (hostInfo, error)
	fstat(f *os.File) (hostInfo, error)
	mkdir(rel string) error
	unlink(rel string) error
	rmdir(rel string) error
	rename(oldRel, newRel string) error
	link(oldRel, newRel string) error
	readlink(rel string) (string, error)
	readDir(rel string) ([]hostDirEntry, error)
	syncDir(rel string) error
	chtimes(rel string, atime, mtime *time.Time) error

	// caseInsensitive reports whether the volume folds name case.
	caseInsensitive() bool
	// caseVerified reports that lstat and openDirAt already compare the
	// stored name with the requested name, so callers need no second check.
	caseVerified() bool

	// rootDir returns the pinned workspace directory.
	rootDir() hostDirHandle
	// openDirAt opens the directory name inside dir. It returns
	// ErrPathTraversal when name is a link and never follows it.
	openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error)
	// closeDir releases a handle that openDirAt returned.
	closeDir(dir hostDirHandle) error
	// fstatDir reads the metadata of the directory that dir names.
	fstatDir(dir hostDirHandle) (hostInfo, error)
	// lstatAt is lstat for name inside dir.
	lstatAt(dir hostDirHandle, name string) (hostInfo, error)
	// openChildAt is open for name inside dir.
	openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error)

	// hostOps holds the host calls of the extended operations of GVXIP-001
	// section 4.3. See host_ops.go.
	hostOps
}

// hostKind is the file type of a host directory entry.
type hostKind uint8

const (
	// hostKindRegular is a regular file.
	hostKindRegular hostKind = iota + 1
	// hostKindDir is a directory.
	hostKindDir
	// hostKindSymlink is a host symbolic link that hostfs may report and read
	// but never traverses.
	hostKindSymlink
	// hostKindOther is any other host object, such as a device, a socket, or a
	// junction. hostfs refuses to open these.
	hostKindOther
	// hostKindSpecial is a placeholder file that stands for a socket, a FIFO,
	// or a device node. The host holds an empty regular file, and .gvx_meta
	// holds the type. Only entryFromInfo produces this kind. The host layer
	// never reports it.
	hostKindSpecial
)

// hostID identifies a host file independent of the path used to reach it.
// Hard links share one hostID.
type hostID struct {
	dev uint64
	ino uint64
}

// hostInfo is the host metadata of one entry, obtained without following
// symbolic links.
type hostInfo struct {
	kind hostKind
	id   hostID
	size int64
	// blocks is the allocation size in 512-byte units.
	blocks int64
	nlink  uint32
	// perm holds the host permission bits. hostfs uses them only as the
	// default virtual mode of entries that have no .gvx_meta record.
	perm  uint32
	atime time.Time
	mtime time.Time
	ctime time.Time
	btime time.Time
}

// hostDirEntry is one name returned by hostRoot.readDir.
type hostDirEntry struct {
	name string
	kind hostKind
	// ino is the host inode number, or zero when the platform layer does not
	// report it during listing.
	ino uint64
}

// errInvalidHostName reports a name that the host file system cannot store
// without changing its meaning, such as a Windows alternate data stream name.
var errInvalidHostName = errors.New("hostfs: name is not representable on the host file system")

// errNameMismatch reports a name that the host resolves only because it folds
// case or accepts a short alias. It wraps fs.ErrNotExist, because the guest
// asked for a name that does not exist. Callers that create names treat it as
// a collision with the stored name.
var errNameMismatch = errors.New("hostfs: the stored name differs from the requested name")

// errHostUnsupported reports an operation that the host file system cannot
// perform, such as a hard link on a volume without hard link support.
var errHostUnsupported = errors.New("hostfs: operation not supported by the host file system")
