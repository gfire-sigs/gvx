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
	"regexp"
	"slices"
	"strings"
)

// copyrightPattern finds the start of a copyright notice. The word must be
// followed by a year, a symbol, or a holder name, so "Grant of Copyright License"
// in a license text does not match.
var copyrightPattern = regexp.MustCompile(`\bCopyright\s+(?:[\d(©]|The\s)`)

// leadingCopyright matches a copyright line at the top of a license text.
var leadingCopyright = regexp.MustCompile(`^\s*Copyright\s`)

// listMarker matches the bullet or the number at the start of a list item.
var listMarker = regexp.MustCompile(`(?m)^[ \t]*(?:\d+\.|\*|-)[ \t]+`)

// placeholderNotices are template texts of license appendices, not notices.
var placeholderNotices = []string{"[yyyy]", "[name of copyright owner]"}

// normalizeLines splits text into lines with LF endings and without trailing blanks.
func normalizeLines(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t\r")
	}
	return lines
}

// trimBlankLines removes the blank lines at both ends of lines.
func trimBlankLines(lines []string) []string {
	start, end := 0, len(lines)
	for start < end && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	return lines[start:end]
}

// dropLeadingCopyright removes the copyright lines and the blank lines before the text.
// The copyright lines of the component stay in its component list.
func dropLeadingCopyright(lines []string) []string {
	i := 0
	for i < len(lines) && (strings.TrimSpace(lines[i]) == "" || leadingCopyright.MatchString(lines[i])) {
		i++
	}
	return lines[i:]
}

// textBody returns the normalized text of one component or notice. Each element of
// texts is one file. The files join with a blank line, and the copyright lines at
// the top of each file are removed.
func textBody(texts []string) string {
	parts := make([]string, 0, len(texts))
	for _, text := range texts {
		lines := trimBlankLines(dropLeadingCopyright(normalizeLines(text)))
		if len(lines) > 0 {
			parts = append(parts, strings.Join(lines, "\n"))
		}
	}
	return strings.Join(parts, "\n\n") + "\n"
}

// matchForm returns the text in the form that SPDX matching compares. The form has
// no copyright lines at the top, no list markers, and single spaces only.
func matchForm(text string) string {
	body := strings.Join(dropLeadingCopyright(normalizeLines(text)), "\n")
	body = listMarker.ReplaceAllString(body, "")
	return strings.Join(strings.Fields(body), " ")
}

// copyrightIn returns the copyright notices of the lines. Each notice starts at the
// word Copyright and ends at the end of its line. Placeholder templates are skipped.
func copyrightIn(lines []string) []string {
	var out []string
	for _, line := range lines {
		loc := copyrightPattern.FindStringIndex(line)
		if loc == nil {
			continue
		}
		notice := strings.TrimSuffix(strings.TrimSpace(line[loc[0]:]), "*/")
		notice = strings.Join(strings.Fields(notice), " ")
		if isPlaceholder(notice) {
			continue
		}
		out = appendDistinct(out, notice)
	}
	return out
}

// isPlaceholder reports whether notice is a template text.
func isPlaceholder(notice string) bool {
	for _, p := range placeholderNotices {
		if strings.Contains(notice, p) {
			return true
		}
	}
	return false
}

// headerLines returns the top comment blocks of a source file that state a license
// or a copyright. A block is a run of comment lines that a blank line ends. The scan
// stops at the first line that is neither blank nor a comment. Build directives and
// package documentation hold no license word, so they are left out.
func headerLines(src string) []string {
	var blocks [][]string
	var cur []string
	inBlock := false
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case inBlock:
			cur = append(cur, line)
			inBlock = !strings.Contains(t, "*/")
		case t == "":
			flush()
		case strings.HasPrefix(t, "//"):
			cur = append(cur, line)
		case strings.HasPrefix(t, "/*"):
			cur = append(cur, line)
			inBlock = !strings.Contains(t, "*/")
		default:
			flush()
			return licenseBlocks(blocks)
		}
	}
	flush()
	return licenseBlocks(blocks)
}

// licenseBlocks joins the blocks that state a license or a copyright, with a blank
// line between them.
func licenseBlocks(blocks [][]string) []string {
	var out []string
	for _, block := range blocks {
		text := strings.Join(block, "\n")
		if !licenseWords.MatchString(text) {
			continue
		}
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, block...)
	}
	return out
}

// appendDistinct appends each value that dst does not hold yet.
func appendDistinct(dst []string, values ...string) []string {
	for _, v := range values {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}
