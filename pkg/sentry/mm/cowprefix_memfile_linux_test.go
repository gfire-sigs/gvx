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

//go:build linux

package mm

import (
	"os"

	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
)

// newCOWTestMemoryFile returns a memory file on a memfd, as the Linux
// Sentry uses.
func newCOWTestMemoryFile() (*pgalloc.MemoryFile, error) {
	fd, err := memutil.CreateMemFD("cowprefix-test", 0)
	if err != nil {
		return nil, err
	}
	return pgalloc.NewMemoryFile(os.NewFile(uintptr(fd), "cowprefix-test"), pgalloc.MemoryFileOpts{})
}
