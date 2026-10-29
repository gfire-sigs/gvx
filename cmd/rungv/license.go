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
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
)

// thirdPartyLicenses is the notice file that tools/licenses writes.
//
//go:embed licenses/THIRD_PARTY_LICENSES.txt
var thirdPartyLicenses string

// componentListHeading starts the component index of the notice file. It must
// match the heading that tools/licenses writes.
const componentListHeading = "Components (name version SPDX-id):"

func init() {
	register(command{
		name:    "license",
		summary: "Print the license texts of rungv and of its components.\n-list prints one line per component: name version SPDX-id.",
		usage:   []string{"rungv license [-list]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return licenseSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// licenseSubcommand prints the notice file, or the component index with -list.
func licenseSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("license", stderr)
	list := fs.Bool("list", false, "print one line per component: name version SPDX-id")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(stderr, "license", "unexpected argument %q", fs.Arg(0))
	}
	if !*list {
		_, _ = io.WriteString(stdout, thirdPartyLicenses)
		return 0
	}
	lines, ok := componentIndex(thirdPartyLicenses)
	if !ok {
		return imageFail(stderr, "license", errors.New("the embedded notice file has no component index"))
	}
	for _, line := range lines {
		_, _ = fmt.Fprintln(stdout, line)
	}
	return 0
}

// componentIndex returns the lines of the component index of text. The index starts
// after componentListHeading and ends at the first blank line.
func componentIndex(text string) ([]string, bool) {
	var lines []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case !in && line == componentListHeading:
			in = true
		case in && line == "":
			return lines, true
		case in:
			lines = append(lines, line)
		}
	}
	return lines, in
}
