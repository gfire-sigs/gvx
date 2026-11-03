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

package hostfs

// windowsMaxWatchedDentries is the cap on Windows. A watched object holds one
// directory handle and one buffer of watchBufferSize bytes, and the process
// handle limit is far above the cap, so memory sets the cap: 32,768 objects hold
// 128 MiB of buffers.
const windowsMaxWatchedDentries = 32768

// hostWatchLimit returns the cap of watched objects.
func hostWatchLimit() int { return windowsMaxWatchedDentries }
