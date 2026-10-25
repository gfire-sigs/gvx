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

//go:build !darwin

package hvf

import (
	"errors"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// Hypervisor.framework exists only on macOS. Every entry point of this file
// reports that, so a Platform never exists on another host.

var errUnsupportedOS = errors.New("hvf: Hypervisor.framework is only available on darwin")

// FrameworkSymbolsLoaded reports whether Hypervisor.framework resolved in the
// current process. It is always false on a host other than macOS.
func FrameworkSymbolsLoaded() bool {
	return false
}

type vmState struct{}

func acquireVM() (*vmState, error) { return nil, errUnsupportedOS }

func releaseVM(*vmState) error { return errUnsupportedOS }

func (*vmState) concurrency() int { return 0 }

func (*vmState) kernelTables() *pagetables.PageTables { return nil }

func (*vmState) retain() error { return errUnsupportedOS }

func (*vmState) release() {}

func (*vmState) AllocPage() ([]byte, uint64, error) { return nil, 0, errUnsupportedOS }

func (*vmState) FreePage([]byte, uint64) {}

func (*vmState) resolveMemory(*regionUser, memmap.File, safemem.BlockSeq, bool) ([]segment, error) {
	return nil, errUnsupportedOS
}

func (*vmState) releaseMemory(*regionUser) {}

func (*vmState) quiesce(*stage1Tables) {}

func (*vmState) retire(pt *stage1Tables) {
	pt.markDead()
	pt.release()
}

func (*vmState) switchContext(context.Context, platform.MemoryManager, *Context, *AddressSpace, *arch.Context64) (*linux.SignalInfo, hostarch.AccessType, error) {
	return nil, hostarch.NoAccess, errUnsupportedOS
}

type contextHW struct{}

func (*contextHW) init() {}

func (*contextHW) cancel() {}
