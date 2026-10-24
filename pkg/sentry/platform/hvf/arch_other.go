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

//go:build !arm64

package hvf

// The engine runs on darwin/arm64 only. The project dropped darwin/amd64. A
// build for any other architecture still compiles the shared code of the
// package, so these constants give it the values that it needs. They never
// reach a running guest.

// maxUserAddress is the end of the user address range of a 48-bit layout.
const maxUserAddress = 1 << 48

// userUpperStart is the first address above the user range.
const userUpperStart = uintptr(maxUserAddress)
