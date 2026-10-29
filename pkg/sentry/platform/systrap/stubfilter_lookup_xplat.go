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

package systrap

import (
	"fmt"
	"runtime"
	"sync"

	"z.gfire.dev/gvx/pkg/seccomp/precompiledseccomp"
	"z.gfire.dev/gvx/pkg/sentry/platform/systrap/stubfilter"
)

// The go branch of gVisor checks in stubfilter_precompiled.go, which its
// generator built on amd64. The programs of another architecture differ in
// their rules and variables, so a program rendered from that file fails on
// arm64 with "called with inconsistent vars". Other architectures build the
// programs from the rules of the stubfilter package, once, as the generator does.
var (
	runtimeStubFiltersOnce sync.Once
	runtimeStubFilters     map[string]precompiledseccomp.Program
	runtimeStubFiltersErr  error
)

// lookupStubFilter returns the program for name and whether it exists.
func lookupStubFilter(name string) (precompiledseccomp.Program, bool) {
	if runtime.GOARCH == "amd64" {
		return GetPrecompiled(name)
	}
	runtimeStubFiltersOnce.Do(func() {
		programs, err := stubfilter.PrecompiledPrograms()
		if err != nil {
			runtimeStubFiltersErr = err
			return
		}
		runtimeStubFilters = make(map[string]precompiledseccomp.Program, len(programs))
		for _, p := range programs {
			runtimeStubFilters[p.Name] = p
		}
	})
	if runtimeStubFiltersErr != nil {
		panic(fmt.Sprintf("cannot build the seccomp programs of the stubs: %v", runtimeStubFiltersErr))
	}
	p, ok := runtimeStubFilters[name]
	return p, ok
}
