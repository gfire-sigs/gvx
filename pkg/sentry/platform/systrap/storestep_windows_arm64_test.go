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

//go:build windows && arm64

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestStoreExclusiveIntoTheExecutingPageStillFaults checks a case that no store
// step serves. Every restart of a store exclusive clears the exclusive monitor,
// so a guest loop around it would never end. The engine reports SIGSEGV.
func TestStoreExclusiveIntoTheExecutingPageStillFaults(t *testing.T) {
	r := newRig(t, newPlatform(t))
	code := gConst(1, codeVA+0x800)
	code = append(code, wordBytes(
		0xc85f7c22, // ldxr x2, [x1]
		0xc8037c22, // stxr w3, x2, [x1]
	)...)
	r.mapPage(codeVA, rwxAccess, code)
	r.mapStack()
	si, at, err := r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
	if at != hostarch.Write {
		t.Errorf("access = %v, want a write", at)
	}
}
