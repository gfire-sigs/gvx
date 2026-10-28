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

//go:build darwin && arm64 && !pagesize_64k

package hostarch

const (
	// PageShift is the binary log of the guest page size (4KB).
	// Apple Silicon hosts run with 16KB hardware pages while Hypervisor.framework
	// presents 4KB guest pages to Linux binaries.
	PageShift = 12

	// HugePageShift is the binary log of the guest huge page size (2MB).
	HugePageShift = 21
)
