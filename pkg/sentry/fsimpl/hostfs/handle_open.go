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

import "os"

// This file opens host files as hostHandle values. Each open registers the
// handle in the same critical section of Workspace.mu as the host open. A
// directory rename holds Workspace.mu for writing, so it finds either no file
// or a registered handle. It never finds an open file that is not registered.

// wrapLocked wraps f, which the host opened for the guest path rel, and
// registers the handle. The caller holds w.mu.
func (w *Workspace) wrapLocked(rel string, f *os.File, flags int) *hostHandle {
	h := newHostHandle(f, flags)
	w.handles.add(h, rel)
	return h
}

// openHandleWithAttr is openRegularWithAttr that returns a registered handle.
func (w *Workspace) openHandleWithAttr(rel string, e entry, flags int) (*hostHandle, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	f, err := w.openRegularWithAttrLocked(rel, e, flags)
	if err != nil {
		return nil, err
	}
	return w.wrapLocked(rel, f, flags), nil
}

// openHandle is openRegular that returns a registered handle.
func (w *Workspace) openHandle(rel string, flags int) (*hostHandle, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	f, _, err := w.openRegularLocked(rel, flags)
	if err != nil {
		return nil, err
	}
	return w.wrapLocked(rel, f, flags), nil
}

// createHandle is createFile that returns a registered handle. The handle
// has read and write access.
func (w *Workspace) createHandle(rel string, perm, uid, gid uint32) (*hostHandle, entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f, e, err := w.createFileLocked(rel, perm, uid, gid)
	if err != nil {
		return nil, entry{}, err
	}
	return w.wrapLocked(rel, f, os.O_RDWR), e, nil
}
