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

package main

import (
	"strings"
	"testing"
)

// madeUpRefs are small reference texts for the matcher tests.
var madeUpRefs = []reference{
	newReference("Made-1.0", "Made up grant.\n\nMade up term that ends the grant."),
	newReference("Made-2.0", "Second made up grant for the other license."),
}

func TestSPDXExpression(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{
			name: "exact reference text",
			text: "Made up grant.\n\nMade up term that ends the grant.",
			want: "Made-1.0",
		},
		{
			name: "reflowed lines and list markers match",
			text: "Intro.\n  1. Made up grant.\n\n   * Made up term\n     that ends the grant.\n",
			want: "Made-1.0",
		},
		{
			name: "copyright line at the top is ignored",
			text: "Copyright 2026 Someone\n\nSecond made up grant for the other license.",
			want: "Made-2.0",
		},
		{
			name: "two licenses join with AND in sorted order",
			text: "Second made up grant for the other license.\n\nMade up grant.\n\nMade up term that ends the grant.",
			want: "Made-1.0 AND Made-2.0",
		},
		{
			name: "text that only partly matches is unknown",
			text: "Made up grant.\n\nA different term.",
			want: noAssertion,
		},
		{
			name: "unrelated text is unknown",
			text: "Something else entirely.",
			want: noAssertion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := spdxExpression(tc.text, madeUpRefs); got != tc.want {
				t.Errorf("spdxExpression(%q) = %q, want %q", tc.text, got, tc.want)
			}
		})
	}
}

func TestSPDXExpressionIgnoresEmptyReference(t *testing.T) {
	refs := []reference{{id: "Empty-1.0", form: ""}}
	if got := spdxExpression("Any text matches an empty form.", refs); got != noAssertion {
		t.Errorf("spdxExpression with an empty reference = %q, want %q", got, noAssertion)
	}
}

// TestEmbeddedReferencesMatchThemselves checks that each embedded reference text
// names its own identifier, so a broken copy of a reference fails the test.
func TestEmbeddedReferencesMatchThemselves(t *testing.T) {
	refs, err := loadReferences()
	if err != nil {
		t.Fatalf("loadReferences() error: %v", err)
	}
	for _, rf := range referenceFileIDs {
		data, err := referenceFiles.ReadFile("spdx/" + rf.file)
		if err != nil {
			t.Fatalf("read %s: %v", rf.file, err)
		}
		if got := spdxExpression(string(data), refs); !strings.Contains(got, rf.id) {
			t.Errorf("%s matches %q, want it to contain %q", rf.file, got, rf.id)
		}
	}
}
