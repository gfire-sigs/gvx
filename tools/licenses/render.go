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
	"fmt"
	"slices"
	"strings"
)

// componentListHeading starts the component index of the text file. The index
// holds one line per component and ends at the first blank line. The command
// rungv license reads the same layout.
const componentListHeading = "Components (name version SPDX-id):"

// textBlock is one license text and the components that use it.
type textBlock struct {
	body       string
	spdx       string
	components []component
}

// dedupe groups the components by their normalized text. Each distinct text appears
// once, at the position of its first component.
func dedupe(components []component) []textBlock {
	index := map[string]int{}
	var blocks []textBlock
	for _, c := range components {
		i, ok := index[c.body]
		if !ok {
			i = len(blocks)
			index[c.body] = i
			blocks = append(blocks, textBlock{body: c.body, spdx: c.spdx})
		}
		blocks[i].components = append(blocks[i].components, c)
	}
	return blocks
}

const introduction = `rungv license notices
=====================

This file lists the licenses of the components in the rungv binary.
The generator "go run ./tools/licenses" writes this file. Do not edit it by hand.
"rungv license" prints this file. "rungv license -list" prints the component index.
`

const noticeIntroduction = `The files below belong to this repository, or to the modules and the standard library that the binary links.
Each notice names the files that carry it. The notices that restate the Go BSD-style license or the MIT SPDX line of a module are omitted, because the license texts above cover them.`

const embeddedNote = `The Go sources name the C sources of the vDSO and sysmsg object files as gVisor files.
This repository does not contain those C sources. Each object file belongs to the component named after it.`

// heading writes a section title with an underline.
func heading(b *strings.Builder, title string) {
	b.WriteString("\n" + title + "\n" + strings.Repeat("=", len(title)) + "\n\n")
}

// text returns the content of the embedded text file.
func (d document) text() string {
	var b strings.Builder
	b.WriteString(introduction)
	fmt.Fprintf(&b, "\nGo version: %s\n", d.goVersion)
	fmt.Fprintf(&b, "Targets: %s. Each target builds with CGO_ENABLED=0.\n", strings.Join(targetNames(), ", "))

	b.WriteString("\n" + componentListHeading + "\n")
	for _, c := range d.components {
		fmt.Fprintf(&b, "%s %s %s\n", c.name, c.version, c.spdx)
	}
	b.WriteString("\n")

	blocks := dedupe(d.components)
	heading(&b, "License texts")
	b.WriteString("Each license text appears once. The components below each text use it.\n")
	for i, blk := range blocks {
		fmt.Fprintf(&b, "\nLicense text %d of %d: %s\n", i+1, len(blocks), blk.spdx)
		b.WriteString(strings.Repeat("-", 40) + "\n\n")
		b.WriteString(blk.body)
		b.WriteString("\nComponents that use this text:\n")
		for _, c := range blk.components {
			fmt.Fprintf(&b, "  %s %s\n", c.name, c.version)
			for _, note := range c.notes {
				fmt.Fprintf(&b, "      note: %s\n", note)
			}
			if len(c.copyright) == 0 {
				b.WriteString("      no copyright notice was found in the license files or the sources\n")
			}
			for _, cr := range c.copyright {
				fmt.Fprintf(&b, "      %s\n", cr)
			}
		}
	}

	if len(d.notices) > 0 {
		heading(&b, "Notices of files with a license other than Apache-2.0")
		b.WriteString(noticeIntroduction + "\n")
		for i, n := range d.notices {
			fmt.Fprintf(&b, "\nNotice %d of %d (SPDX: %s)\n", i+1, len(d.notices), n.spdx)
			fmt.Fprintf(&b, "Files: %s\n", strings.Join(n.paths, ", "))
			if len(n.copyright) > 0 {
				b.WriteString("Copyright lines:\n")
				for _, cr := range n.copyright {
					fmt.Fprintf(&b, "  %s\n", cr)
				}
			}
			b.WriteString(strings.Repeat("-", 40) + "\n\n")
			b.WriteString(n.text + "\n")
		}
	}

	heading(&b, "Files embedded in the rungv binary")
	b.WriteString(embeddedNote + "\n\n")
	for _, e := range d.embeds {
		fmt.Fprintf(&b, "%s %s: %s\n", e.importPath, e.file, e.owner)
	}
	return b.String()
}

// markdownTable returns the README table of the third-party modules, one row per
// SPDX identifier.
func (d document) markdownTable() string {
	byID := map[string][]component{}
	var ids []string
	for _, c := range d.components {
		if c.group != groupModule {
			continue
		}
		if _, ok := byID[c.spdx]; !ok {
			ids = append(ids, c.spdx)
		}
		byID[c.spdx] = append(byID[c.spdx], c)
	}
	slices.Sort(ids)

	var b strings.Builder
	b.WriteString("| SPDX identifier | Third-party modules |\n")
	b.WriteString("| :--- | :--- |\n")
	for _, id := range ids {
		cells := make([]string, 0, len(byID[id]))
		for _, c := range byID[id] {
			cell := fmt.Sprintf("`%s` %s", c.name, c.version)
			if c.replacement != "" {
				cell += fmt.Sprintf(" (local copy in `%s`)", strings.TrimPrefix(c.replacement, "./"))
			}
			cells = append(cells, cell)
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", id, strings.Join(cells, ", "))
	}
	return b.String()
}
