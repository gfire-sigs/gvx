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
	"slices"
	"strings"
	"testing"
)

// madeUpComponent returns a module component whose license file holds text.
func madeUpComponent(name string, copyright []string, text string) component {
	return newComponent(componentSpec{
		name:      name,
		version:   "v1.0.0",
		group:     groupModule,
		copyright: copyright,
		licenses:  []string{text},
	}, nil)
}

func TestDedupeSharesEqualTexts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		components []component
		// wantBlocks lists the components of each printed text, by name.
		wantBlocks [][]string
	}{
		{
			name: "line endings and trailing blanks do not split a text",
			components: []component{
				madeUpComponent("a", nil, "Alpha grant\nBeta term\n"),
				madeUpComponent("b", nil, "Alpha grant\r\nBeta term   \r\n\n"),
			},
			wantBlocks: [][]string{{"a", "b"}},
		},
		{
			name: "copyright lines at the top do not split a text",
			components: []component{
				madeUpComponent("a", []string{"Copyright 2001 A"}, "Copyright 2001 A\n\nAlpha grant\n"),
				madeUpComponent("b", []string{"Copyright 2009 B"}, "Copyright 2009 B\n\nAlpha grant\n"),
			},
			wantBlocks: [][]string{{"a", "b"}},
		},
		{
			name: "different terms print separate texts in first-use order",
			components: []component{
				madeUpComponent("a", nil, "Alpha grant\n"),
				madeUpComponent("b", nil, "Gamma grant\n"),
				madeUpComponent("c", nil, "Alpha grant\n"),
			},
			wantBlocks: [][]string{{"a", "c"}, {"b"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocks := dedupe(tc.components)
			if len(blocks) != len(tc.wantBlocks) {
				t.Fatalf("dedupe produced %d texts, want %d", len(blocks), len(tc.wantBlocks))
			}
			for i, want := range tc.wantBlocks {
				var got []string
				for _, c := range blocks[i].components {
					got = append(got, c.name)
				}
				if !slices.Equal(got, want) {
					t.Errorf("text %d is used by %v, want %v", i, got, want)
				}
			}
		})
	}
}

func TestDedupeKeepsEveryCopyrightLine(t *testing.T) {
	blocks := dedupe([]component{
		madeUpComponent("a", []string{"Copyright 2001 A"}, "Copyright 2001 A\n\nAlpha grant\n"),
		madeUpComponent("b", []string{"Copyright 2009 B"}, "Copyright 2009 B\n\nAlpha grant\n"),
	})
	if len(blocks) != 1 {
		t.Fatalf("dedupe produced %d texts, want 1", len(blocks))
	}
	if strings.Contains(blocks[0].body, "Copyright") {
		t.Errorf("printed text %q holds a copyright line that the component lists would repeat", blocks[0].body)
	}
	for _, c := range blocks[0].components {
		if len(c.copyright) != 1 {
			t.Errorf("component %s lost its copyright line: %v", c.name, c.copyright)
		}
	}
}

func TestMarkdownTableListsModulesBySPDX(t *testing.T) {
	refs := []reference{newReference("MIT", "Permission is hereby granted for the made up text.")}
	mit := newComponent(componentSpec{name: "example.com/mit", version: "v1.0.0", group: groupModule,
		licenses: []string{"Permission is hereby granted for the made up text."}}, refs)
	other := newComponent(componentSpec{name: "example.com/other", version: "v2.0.0", group: groupModule,
		replacement: "./third_party/other", licenses: []string{"Unknown text."}}, refs)
	doc := document{components: []component{mit, other}}
	want := "| SPDX identifier | Third-party modules |\n" +
		"| :--- | :--- |\n" +
		"| `MIT` | `example.com/mit` v1.0.0 |\n" +
		"| `NOASSERTION` | `example.com/other` v2.0.0 (local copy in `third_party/other`) |\n"
	if got := doc.markdownTable(); got != want {
		t.Errorf("markdownTable() =\n%s\nwant\n%s", got, want)
	}
}
