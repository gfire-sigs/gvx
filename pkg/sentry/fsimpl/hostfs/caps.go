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
	"sync/atomic"
	"time"
)

// WorkspaceCaps records the native capabilities of the mounted host volume.
// OpenWorkspace probes them once, before the sandbox lockdown. Each flag
// selects between a direct host call and a translation path.
type WorkspaceCaps struct {
	// CaseSensitive reports that the volume keeps names that differ only in
	// case apart.
	CaseSensitive bool
	// UnicodeNormalized reports that the volume treats the NFC and NFD forms
	// of a name as one name.
	UnicodeNormalized bool
	// RestrictsWinNames reports that the volume rejects the Windows reserved
	// names and characters.
	RestrictsWinNames bool
	// LocksOpenDirMove reports that the host refuses to rename a directory
	// that has an open descendant.
	LocksOpenDirMove bool
	// NativeXattr reports that the host stores extended attributes on files.
	NativeXattr bool
	// NativeRenameSwap reports that the host exchanges two names atomically.
	NativeRenameSwap bool
	// NativeFallocate reports that the host preallocates file space.
	NativeFallocate bool
}

// Caps returns the capabilities of the host volume that the probe recorded.
func (w *Workspace) Caps() WorkspaceCaps {
	return w.caps
}

// probeSeq makes the names of probe files unique in one process.
var probeSeq atomic.Uint64

// probeBase returns the start of a probe file name. The name holds the process
// number and the time, so a probe file that a killed process left behind never
// collides with a new one.
func probeBase() string {
	return fmt.Sprintf(".gvx-probe-%x-%x-%x-", os.Getpid(), time.Now().UnixNano(), probeSeq.Add(1))
}

// createProbeFile creates the empty probe file name in the workspace root. The
// returned function removes the file.
func createProbeFile(host hostBackend, name string) (*os.File, func(), error) {
	f, err := host.open(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func() {
		_ = f.Close()
		_ = host.unlink(name)
	}, nil
}
