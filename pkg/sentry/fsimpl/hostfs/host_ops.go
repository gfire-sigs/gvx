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

// hostOps holds the host calls of the extended operations of GVXIP-001
// section 4.3. Each platform file set implements them on hostRoot. A call that
// the host cannot perform returns errHostUnsupported, and the caller then takes
// the translation path that the volume capabilities name.
type hostOps interface {
	// exchange swaps the entries oldRel and newRel in one atomic host call.
	// Both entries must exist. Only a host with WorkspaceCaps.NativeRenameSwap
	// implements it.
	exchange(oldRel, newRel string) error

	// statfs reports the capacity of the volume that holds the workspace.
	statfs() (hostVolume, error)

	// openAnonAt creates an unnamed regular file in the directory dir and
	// returns it open for reading and writing. The host removes the file when
	// the last descriptor closes. Only Linux implements it.
	openAnonAt(dir hostDirHandle) (*os.File, error)
}
