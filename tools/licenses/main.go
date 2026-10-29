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

// Command licenses collects the license notices of the rungv binary. It writes
// them as one text file that cmd/rungv embeds. It also checks that the embedded
// file and the README table are current.
//
// Run the command from the root of the repository. The command runs go list
// for each shipped target, so the module cache must hold the dependencies.
// The package cmd/rungv embeds the text file, so go list fails when the file is
// missing. Create an empty file at the default path once before the first run.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Paths of the generated files, relative to the repository root.
const (
	defaultEmbedded = "cmd/rungv/licenses/THIRD_PARTY_LICENSES.txt"
	defaultReadme   = "README.md"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one mode of the command and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("licenses", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "write the notice text to `FILE`")
	check := fs.Bool("check", false, "fail when the embedded file or the README table is stale")
	markdown := fs.Bool("markdown", false, "print the README table of the third-party modules")
	embedded := fs.String("embedded", defaultEmbedded, "embedded text file that -check compares")
	readme := fs.String("readme", defaultReadme, "README file that -check compares")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "licenses: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	modes := 0
	for _, set := range []bool{*out != "", *check, *markdown} {
		if set {
			modes++
		}
	}
	if modes != 1 {
		_, _ = fmt.Fprintln(stderr, "licenses: choose exactly one of -o, -check, or -markdown")
		fs.Usage()
		return 2
	}

	doc, warnings, err := collectDocument(".")
	for _, w := range warnings {
		_, _ = fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "licenses: %v\n", err)
		return 1
	}
	switch {
	case *out != "":
		if err := os.WriteFile(*out, []byte(doc.text()), 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "licenses: %v\n", err)
			return 1
		}
		return 0
	case *markdown:
		_, _ = io.WriteString(stdout, doc.markdownTable())
		return 0
	default:
		return checkDocument(doc, *embedded, *readme, stdout, stderr)
	}
}

// checkDocument reports whether the embedded file and the README table match doc.
func checkDocument(doc document, embeddedPath, readmePath string, stdout, stderr io.Writer) int {
	stale := false
	want := doc.text()
	have, err := os.ReadFile(embeddedPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "licenses: %v\n", err)
		return 1
	}
	if string(have) != want {
		stale = true
		_, _ = fmt.Fprintf(stderr, "%s is stale; regenerate it with: go run ./tools/licenses -o %s\n", embeddedPath, embeddedPath)
		_, _ = io.WriteString(stderr, diffSummary(string(have), want))
	}

	readme, err := os.ReadFile(readmePath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "licenses: %v\n", err)
		return 1
	}
	if table := doc.markdownTable(); !strings.Contains(string(readme), table) {
		stale = true
		_, _ = fmt.Fprintf(stderr, "%s does not contain the current license table; paste the output of: go run ./tools/licenses -markdown\n", readmePath)
	}
	if stale {
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "license notices are current")
	return 0
}

// diffSummary lists the lines that differ between have and want. It prints at most
// maxDiffLines lines and then a count of the remaining ones.
func diffSummary(have, want string) string {
	const maxDiffLines = 40
	a := strings.Split(have, "\n")
	b := strings.Split(want, "\n")
	// lcs[i][j] is the length of the longest common subsequence of a[i:] and b[j:].
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var sb strings.Builder
	differing := 0
	emit := func(prefix, line string) {
		differing++
		if differing <= maxDiffLines {
			_, _ = fmt.Fprintf(&sb, "%s %s\n", prefix, line)
		}
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i++
			j++
		case j < len(b) && (i == len(a) || lcs[i][j+1] >= lcs[i+1][j]):
			emit("+", b[j])
			j++
		default:
			emit("-", a[i])
			i++
		}
	}
	if differing > maxDiffLines {
		_, _ = fmt.Fprintf(&sb, "... %d more differing lines\n", differing-maxDiffLines)
	}
	return sb.String()
}
