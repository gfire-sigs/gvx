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

//go:build arm64 && pagesize_16k && !pagesize_64k

package hostarch

const (
	// PageShift is the binary log of the system page size.
	// 16K pages: 2^14 = 16384. This matches the Apple Silicon VM page size,
	// which the macOS systrap backend needs to map guest pages natively.
	PageShift = 14

	// HugePageShift is the binary log of the system huge page size.
	// For 16K pages: PageShift + (PageShift - 3) = 14 + 11 = 25
	// This gives 32MB huge pages.
	HugePageShift = 25
)
