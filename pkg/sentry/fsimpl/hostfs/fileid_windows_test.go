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

package hostfs

import "testing"

func TestPathAtOrBelow(t *testing.T) {
	for _, tc := range []struct {
		path, root string
		want       bool
	}{
		{`\ws`, `\ws`, true},
		{`\ws\a\b`, `\ws`, true},
		{`\WS\A`, `\ws`, true},
		{`\ws2`, `\ws`, false},
		{`\ws2\a`, `\ws`, false},
		{`\other\ws`, `\ws`, false},
		{`\$Recycle.Bin\S-1\$R1`, `\Users\me\ws`, false},
		{`\Users\me`, `\Users\me\ws`, false},
		{`\Users\me\ws\a`, `\Users\me\ws\`, true},
		{`\anything`, `\`, true},
		{`\`, `\`, true},
		{`\Ünï\a`, `\ünï`, true},
	} {
		if got := pathAtOrBelow(tc.path, tc.root); got != tc.want {
			t.Errorf("pathAtOrBelow(%q, %q) = %t, want %t", tc.path, tc.root, got, tc.want)
		}
	}
}
