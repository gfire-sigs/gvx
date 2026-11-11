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

//go:build windows

package fd

import (
	"sync/atomic"

	"golang.org/x/sys/windows"
)

// WindowsFileBroker performs capability-checked file operations beneath host
// mount handles pinned before hostlockdown.Apply().
type WindowsFileBroker interface {
	// OpenAt opens one component relative to dir without following reparse points.
	OpenAt(dir windows.Handle, name string, access, fileAttrs, disposition, options uint32) (windows.Handle, error)

	// OpenWatchHandle opens an overlapped directory handle for dir.
	OpenWatchHandle(dir windows.Handle) (windows.Handle, error)

	// RemoveAt deletes name inside dir with POSIX unlink or rmdir semantics.
	RemoveAt(dir windows.Handle, name string, wantDir bool) error

	// SetTargetNameAt renames or hard-links oldName in oldDir to newName in newDir.
	SetTargetNameAt(oldDir windows.Handle, oldName string, newDir windows.Handle, newName string, access, flags, infoClass uint32) error

	// ExistsByID reports whether a file with the 128-bit NTFS FileID still lies at or below root.
	ExistsByID(root windows.Handle, id [16]byte) (bool, error)

	// FinalPathLeaf returns the stored leaf name of handle inside dir.
	FinalPathLeaf(dir, handle windows.Handle) (string, error)
}

type brokerHolder struct {
	broker WindowsFileBroker
}

type binderHolder struct {
	bind func() error
}

var (
	installedBroker atomic.Pointer[brokerHolder]
	installedBinder atomic.Pointer[binderHolder]
)

// InstallWindowsFileBroker registers the process-wide WindowsFileBroker. Once
// installed, later calls with a non-nil broker do not replace the sealed broker.
func InstallWindowsFileBroker(b WindowsFileBroker) {
	if b == nil {
		return
	}
	installedBroker.CompareAndSwap(nil, &brokerHolder{broker: b})
}

// ActiveWindowsFileBroker returns the installed WindowsFileBroker, or nil before
// hostlockdown.Apply() installs one.
func ActiveWindowsFileBroker() WindowsFileBroker {
	h := installedBroker.Load()
	if h == nil {
		return nil
	}
	return h.broker
}

// RegisterThreadBinder installs the callback that attaches the restricted
// impersonation token to the calling OS thread before host path operations.
func RegisterThreadBinder(bind func() error) {
	if bind == nil {
		return
	}
	installedBinder.CompareAndSwap(nil, &binderHolder{bind: bind})
}

func bindThreadIfLocked() {
	if h := installedBinder.Load(); h != nil {
		_ = h.bind()
	}
}
