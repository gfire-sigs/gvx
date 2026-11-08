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

package pgalloc

import "z.gfire.dev/gvx/pkg/sentry/memmap"

// hostWriteHooks is empty on macOS, whose platforms map the pages of the
// memory file themselves. Such a platform sees every write of the Sentry.
type hostWriteHooks struct{}

// noteHostWrite does nothing on this host.
func (f *MemoryFile) noteHostWrite(memmap.FileRange) {}
