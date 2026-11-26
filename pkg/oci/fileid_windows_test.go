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

package oci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsFileIDStructLayoutsAndRealHandle(t *testing.T) {
	if got := unsafe.Sizeof(ociFileIDInfo{}); got != 24 {
		t.Errorf("sizeof(ociFileIDInfo) = %d, want 24", got)
	}
	if got := unsafe.Sizeof(ociFileBasicInfo{}); got != 40 {
		t.Errorf("sizeof(ociFileBasicInfo) = %d, want 40", got)
	}
	if got := unsafe.Offsetof(ociFileBasicInfo{}.FileAttributes); got != 32 {
		t.Errorf("offsetof(ociFileBasicInfo.FileAttributes) = %d, want 32", got)
	}

	p := filepath.Join(t.TempDir(), "probe.bin")
	if err := os.WriteFile(p, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := openShared(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	id, ok := fileIdentity(f)
	if !ok {
		t.Skip("host filesystem does not expose 128-bit FileIdInfo")
	}
	if !strings.HasPrefix(id.token, "w1:") || !strings.HasPrefix(id.handleKey, "w1:") || id.writeStamp == "" {
		t.Errorf("unexpected Windows fileID = %+v", id)
	}
	if diff := time.Since(id.changeTime); diff < -time.Minute || diff > time.Minute {
		t.Errorf("Windows changeTime = %v deviates from wall clock by %v", id.changeTime, diff)
	}
}
