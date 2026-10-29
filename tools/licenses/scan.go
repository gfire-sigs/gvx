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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// sourceExtensions are the file kinds whose headers the scan reads.
var sourceExtensions = map[string]bool{".go": true, ".s": true, ".S": true, ".c": true, ".h": true}

// apacheMarker names the Apache-2.0 license in a header.
const apacheMarker = "Licensed under the Apache License, Version 2.0"

// licenseWords mark a header that states a license or a copyright.
var licenseWords = regexp.MustCompile(`(?i)license|copyright|permission|redistribution|spdx|governed by`)

// directivePrefixes start the build and tool lines that a notice omits.
var directivePrefixes = []string{"go:", "+build"}

// headerNotices are the one-sentence license notices of the Go project and of
// WireGuard. A header block can carry descriptive comments after one of these
// sentences, so the scan keeps only the sentence. A linked file whose notice is one
// of these sentences restates a component license, and the scan omits it.
var headerNotices = []string{
	"Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.",
	"Use of this source code is governed by a BSD-style license that can be found in the LICENSE file or at https://developers.google.com/open-source/licenses/bsd.",
	"SPDX-License-Identifier: MIT",
}

// headerKind classifies the header of a source file.
type headerKind int

const (
	headerNone headerKind = iota
	headerApache
	headerOther
)

// sourceFile is one source file that the scan reads.
type sourceFile struct {
	path string
	// label names the file in the notice file.
	label string
	// linked marks a file of a module or of the standard library. The scan omits
	// the notices of these files that restate a component license.
	linked bool
}

// repoScan holds the license data of the source files of the scan.
type repoScan struct {
	// apacheCopyrights are the distinct copyright notices of the files under Apache-2.0
	// that belong to this repository.
	apacheCopyrights []string
	// others are the headers that state a license other than Apache-2.0.
	others []sourceNotice
}

// sourceNotice is one header text and the files that carry it.
type sourceNotice struct {
	text       string
	copyrights []string
	paths      []string
}

// isSourceFile reports whether name is a source file that the scan reads.
func isSourceFile(name string) bool {
	return sourceExtensions[filepath.Ext(name)] && !strings.HasSuffix(name, "_test.go")
}

// repoSourceFiles lists the source files under root. It skips the third_party
// directory, which holds vendored modules, the embedded copy of the x/sys unix
// package, whose license the module golang.org/x/sys already names, and the
// hidden directories.
func repoSourceFiles(root string) ([]sourceFile, error) {
	var files []sourceFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "third_party" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if rel, err := filepath.Rel(root, p); err == nil && filepath.ToSlash(rel) == "internal/xsys" {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExtensions[filepath.Ext(p)] {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, sourceFile{path: p, label: filepath.ToSlash(rel)})
		return nil
	})
	return files, err
}

// linkedSourceFiles lists the source files of the packages that the binary links.
// A module file is labeled with its module path, and a standard library file with
// the prefix std.
func linkedSourceFiles(inv inventory, goroot string) ([]sourceFile, error) {
	var files []sourceFile
	for _, mod := range sortedKeys(inv.modules) {
		listed, err := listSourceDirs(inv.modules[mod].Dir, mod, inv.moduleDirs[mod])
		if err != nil {
			return nil, err
		}
		files = append(files, listed...)
	}
	listed, err := listSourceDirs(filepath.Join(goroot, "src"), "std", inv.stdDirs)
	if err != nil {
		return nil, err
	}
	return append(files, listed...), nil
}

// listSourceDirs lists the source files of dirs. The label of each file joins prefix,
// the directory path below base, and the file name.
func listSourceDirs(base, prefix string, dirs map[string]bool) ([]sourceFile, error) {
	var files []sourceFile
	for _, dir := range sortedKeys(dirs) {
		rel, err := filepath.Rel(base, dir)
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !isSourceFile(e.Name()) {
				continue
			}
			files = append(files, sourceFile{
				path:   filepath.Join(dir, e.Name()),
				label:  path.Join(prefix, filepath.ToSlash(rel), e.Name()),
				linked: true,
			})
		}
	}
	return files, nil
}

// scanSources reads the headers of files and groups the notices of other licenses.
func scanSources(files []sourceFile) (repoScan, error) {
	var scan repoScan
	byText := map[string]*sourceNotice{}
	for _, f := range files {
		src, err := os.ReadFile(f.path)
		if err != nil {
			return repoScan{}, err
		}
		lines := headerLines(string(src))
		switch classifyHeader(lines) {
		case headerApache:
			if !f.linked {
				scan.apacheCopyrights = appendDistinct(scan.apacheCopyrights, copyrightIn(lines)...)
			}
		case headerOther:
			text, copyrights := noticeParts(lines)
			text = leadingNotice(text)
			if f.linked && slices.Contains(headerNotices, text) {
				continue
			}
			n := byText[text]
			if n == nil {
				n = &sourceNotice{text: text}
				byText[text] = n
			}
			n.copyrights = appendDistinct(n.copyrights, copyrights...)
			n.paths = append(n.paths, f.label)
		}
	}
	for _, n := range byText {
		slices.Sort(n.paths)
		scan.others = append(scan.others, *n)
	}
	slices.SortFunc(scan.others, func(a, b sourceNotice) int {
		return strings.Compare(a.paths[0], b.paths[0])
	})
	return scan, nil
}

// classifyHeader reports which license a header states.
func classifyHeader(lines []string) headerKind {
	text := strings.Join(lines, "\n")
	switch {
	case strings.Contains(text, apacheMarker):
		return headerApache
	case licenseWords.MatchString(text):
		return headerOther
	default:
		return headerNone
	}
}

// noticeParts splits a header into its text and its copyright notices. The text
// has no comment markers, no directive lines, and no copyright lines.
func noticeParts(lines []string) (string, []string) {
	var out []string
	var copyrights []string
	for _, line := range lines {
		if found := copyrightIn([]string{line}); len(found) > 0 {
			copyrights = appendDistinct(copyrights, found...)
			continue
		}
		t := strings.TrimSpace(line)
		t = strings.TrimPrefix(t, "//")
		t = strings.TrimPrefix(t, "/*")
		t = strings.TrimSuffix(t, "*/")
		t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "*"))
		if slices.ContainsFunc(directivePrefixes, func(p string) bool { return strings.HasPrefix(t, p) }) {
			continue
		}
		out = append(out, t)
	}
	return strings.Join(trimBlankLines(out), "\n"), copyrights
}

// leadingNotice returns the header notice that text starts with, or text itself
// when no header notice starts it.
func leadingNotice(text string) string {
	form := matchForm(text)
	for _, n := range headerNotices {
		if strings.HasPrefix(form, matchForm(n)) {
			return n
		}
	}
	return text
}

// noticeDocuments converts the header notices of the scan into notices of the
// document. It names the SPDX identifier of each notice.
func noticeDocuments(scan repoScan, refs []reference) ([]notice, []string) {
	var notices []notice
	var warnings []string
	for _, n := range scan.others {
		id := spdxExpression(n.text, refs)
		if id == noAssertion {
			warnings = append(warnings, "no SPDX text matches the notice of "+n.paths[0]+"; its identifier is "+noAssertion)
		}
		notices = append(notices, notice{text: n.text, spdx: id, paths: n.paths, copyright: n.copyrights})
	}
	return notices, warnings
}
