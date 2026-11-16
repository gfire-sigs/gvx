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

package gvx

import (
	"errors"
	"testing"
	"testing/synctest"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

type memoryLifetimePlatform struct {
	platform.Platform
	close func() error
}

func (p memoryLifetimePlatform) Close() error { return p.close() }

func TestSandboxCloseKeepsBackingUntilPlatformCloses(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		name := "pending"
		if consumed {
			name = "consumed"
		}
		t.Run(name, func(t *testing.T) {
			testSandboxBackingLifetime(t, consumed, nil)
		})
		t.Run(name+"/platform_failure", func(t *testing.T) {
			testSandboxBackingLifetime(t, consumed, errors.New("partition teardown failed"))
		})
	}
}

func testSandboxBackingLifetime(t *testing.T, consumed bool, closeErr error) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		mf, err := createKernelMemoryFile(0)
		if err != nil {
			t.Fatal(err)
		}
		backing := mf.File()
		closes := 0
		sb := &Sandbox{
			memFile: mf,
			plat: memoryLifetimePlatform{close: func() error {
				closes++
				synctest.Wait()
				if _, err := backing.Stat(); err != nil {
					t.Errorf("backing file closed before platform teardown: %v", err)
				}
				return closeErr
			}},
		}
		if consumed {
			sb.memFile, sb.runMemFile = nil, mf
		}
		if closeErr != nil {
			defer mf.Destroy()
		}
		if err := sb.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("Close = %v, want %v", err, closeErr)
		}
		synctest.Wait()
		_, statErr := backing.Stat()
		if closeErr == nil && statErr == nil {
			t.Error("backing file remains open after successful platform teardown")
		}
		if closeErr != nil && statErr != nil {
			t.Errorf("backing file closed after failed platform teardown: %v", statErr)
		}
		if err := sb.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("second Close = %v, want %v", err, closeErr)
		}
		if closes != 1 {
			t.Errorf("platform closed %d times, want 1", closes)
		}
	})
}
