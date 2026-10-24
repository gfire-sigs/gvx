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

//go:build !linux

package hostfs

// macOS and Windows keep every extended attribute in .gvx_meta, so
// WorkspaceCaps.NativeXattr is false there. These functions exist so that a
// test can set the flag on any host. Each call then reports that the host
// refuses it, and the meta store takes the attribute.

func nativeXattrRefused(err error) bool { return false }

func nativeXattrNoData(err error) bool { return false }

func nativeXattrError(err error) error { return translateHostError(err) }

func (w *Workspace) nativeGetXattr(t xattrTarget, name string) ([]byte, error) {
	return nil, errHostUnsupported
}

func (w *Workspace) nativeListXattr(t xattrTarget) ([]string, error) {
	return nil, errHostUnsupported
}

func (w *Workspace) nativeSetXattr(t xattrTarget, name string, value []byte, flags uint32) error {
	return errHostUnsupported
}

func (w *Workspace) nativeRemoveXattr(t xattrTarget, name string) error {
	return errHostUnsupported
}
