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

package sys

import (
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestParseModuleUintFollowsKstrtouint(t *testing.T) {
	good := map[string]uint32{
		"0": 0, "7\n": 7, "100": 100, "0x10": 16, "0X1f\n": 31, "010": 8, "4294967295": 4294967295,
	}
	for text, want := range good {
		if got, err := parseModuleUint(text); err != nil || got != want {
			t.Errorf("parseModuleUint(%q) = %d, %v, want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", "\n", "x", "-1", "+1", "1 ", " 1", "1\n\n", "0x", "08", "1_0", "1.5"} {
		if got, err := parseModuleUint(text); !errors.Is(err, linuxerr.EINVAL) {
			t.Errorf("parseModuleUint(%q) = %d, %v, want EINVAL", text, got, err)
		}
	}
	for _, text := range []string{"4294967296", "99999999999999999999", "0x100000000"} {
		if got, err := parseModuleUint(text); !errors.Is(err, linuxerr.ERANGE) {
			t.Errorf("parseModuleUint(%q) = %d, %v, want ERANGE", text, got, err)
		}
	}
}
