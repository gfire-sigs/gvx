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
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

func init() {
	register(command{
		name:    "version",
		summary: "Print the version, the source commit, and the Go toolchain of this binary.",
		usage:   []string{"rungv version", "rungv --version"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return versionSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// versionSubcommand prints the build identity that the Go toolchain records in
// the binary. A build in a clean checkout of a tag records the tag as the
// module version, so a release needs no linker flag.
func versionSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("version", stderr)
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(stderr, "version", "unexpected argument %q", fs.Arg(0))
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		_, _ = fmt.Fprintf(stdout, "rungv (unknown)\ngo %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}
	_, _ = io.WriteString(stdout, formatVersion(info))
	return 0
}

// formatVersion renders the module version, the VCS settings, and the
// toolchain and architecture level of info, one item per line.
func formatVersion(info *debug.BuildInfo) string {
	settings := make(map[string]string, len(info.Settings))
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	out := fmt.Sprintf("rungv %s\n", info.Main.Version)
	if rev, ok := settings["vcs.revision"]; ok {
		out += "commit " + rev
		if t, ok := settings["vcs.time"]; ok {
			out += " (" + t + ")"
		}
		if settings["vcs.modified"] == "true" {
			out += " modified"
		}
		out += "\n"
	}
	goos := settings["GOOS"]
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := settings["GOARCH"]
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	line := fmt.Sprintf("go %s %s/%s", info.GoVersion, goos, goarch)
	if level := archLevel(goarch, settings); level != "" {
		line += " " + level
	}
	return out + line + "\n"
}

func archLevel(goarch string, settings map[string]string) string {
	var key string
	switch goarch {
	case "amd64":
		key = "GOAMD64"
	case "arm64":
		key = "GOARM64"
	case "arm":
		key = "GOARM"
	case "386":
		key = "GO386"
	default:
		return ""
	}
	val := settings[key]
	if val == "" {
		return ""
	}
	return key + "=" + val
}
