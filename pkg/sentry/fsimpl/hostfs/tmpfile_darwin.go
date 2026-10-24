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

//go:build darwin

package hostfs

import "os"

// tmpfileUnlinkAtOnce is false on macOS. The named file stays until the last
// reference goes away, as GVXIP-001 section 4.3 requires.
const tmpfileUnlinkAtOnce = false

// openAnon reports that macOS has no O_TMPFILE. Workspace then creates a
// named "~gvx~tmp" file and removes it when the last reference goes away.
func openAnon(int) (*os.File, error) {
	return nil, errHostUnsupported
}

// anonUnsupported reports whether err means that the host has no O_TMPFILE.
func anonUnsupported(err error) bool {
	return err != nil
}
