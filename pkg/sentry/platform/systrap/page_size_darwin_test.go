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

//go:build darwin && arm64

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestNewSupportsConfiguredGuestPageSize checks that New succeeds with 4KB and
// 16KB guest page sizes on a 16KB Apple silicon host.
func TestNewSupportsConfiguredGuestPageSize(t *testing.T) {
	if hostarch.PageSize != subBlockSize && hostarch.PageSize != blockSize {
		t.Fatalf("unexpected hostarch.PageSize = %d", hostarch.PageSize)
	}
	p, err := New()
	if err != nil {
		t.Fatalf("New() with %dB guest pages failed: %v", hostarch.PageSize, err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
