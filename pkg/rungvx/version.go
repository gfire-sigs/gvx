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

package rungvx

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

// BuildInfoOptions configures nginx-style build-option output in FormatVersion.
type BuildInfoOptions struct {
	// Verbose appends compiler, buildmode, trimpath, SPI version, and per-
	// extension capability lines (`rungvx version -V` / `rungvx -V`).
	Verbose bool
	// Plugins lists the compile-time CLI plugins linked into the binary.
	Plugins []CLIPlugin
}

func init() {
	register(command{
		name:    "version",
		summary: "Print the version, commit, Go toolchain, and compile-time build options.",
		usage:   []string{"rungvx version [-V]", "rungvx --version", "rungvx -V"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return versionSubcommandWithPlugins(ctx, args, streams.stdout, streams.stderr, streams.plugins)
		},
	})
}

func versionSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return versionSubcommandWithPlugins(ctx, args, stdout, stderr, nil)
}

// versionSubcommandWithPlugins prints the build identity and compile-time build
// options that the Go toolchain records in the binary. A build in a clean
// checkout of a tag records the tag as the module version, so a release needs
// no linker flag.
func versionSubcommandWithPlugins(_ context.Context, args []string, stdout, stderr io.Writer, plugins []CLIPlugin) int {
	fs := newImageFlagSet("version", stderr)
	verbose := fs.Bool("V", false, "print verbose compiler, buildmode, SPI, and extension details")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(stderr, "version", "unexpected argument %q", fs.Arg(0))
	}
	opts := BuildInfoOptions{
		Verbose: *verbose,
		Plugins: plugins,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = &debug.BuildInfo{
			GoVersion: runtime.Version(),
			Main:      debug.Module{Version: "(unknown)"},
		}
	}
	_, _ = io.WriteString(stdout, FormatVersion(info, opts))
	return 0
}

// FormatVersion renders the module version, VCS settings, toolchain and
// architecture level, and nginx-style compile-time build options.
func FormatVersion(info *debug.BuildInfo, opts BuildInfoOptions) string {
	if info == nil {
		info = &debug.BuildInfo{
			GoVersion: runtime.Version(),
			Main:      debug.Module{Version: "(unknown)"},
		}
	}
	settings := make(map[string]string, len(info.Settings))
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}

	var b strings.Builder
	ver := info.Main.Version
	if ver == "" {
		ver = "(unknown)"
	}
	fmt.Fprintf(&b, "rungvx %s\n", ver)
	if rev, ok := settings["vcs.revision"]; ok {
		b.WriteString("commit " + rev)
		if t, ok := settings["vcs.time"]; ok {
			b.WriteString(" (" + t + ")")
		}
		if settings["vcs.modified"] == "true" {
			b.WriteString(" modified")
		}
		b.WriteByte('\n')
	}
	goos := settings["GOOS"]
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := settings["GOARCH"]
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	goVer := info.GoVersion
	if goVer == "" {
		goVer = runtime.Version()
	}
	fmt.Fprintf(&b, "go %s %s/%s", goVer, goos, goarch)
	if level := archLevel(goarch, settings); level != "" {
		b.WriteString(" " + level)
	}
	b.WriteByte('\n')

	cgoVal := settings["CGO_ENABLED"]
	if cgoVal != "1" {
		cgoVal = "0"
	}
	tagsVal := formatBuildTags(settings["-tags"])
	extNames, sortedPlugins := sortedPluginMetadata(opts.Plugins)
	extsVal := "none"
	if len(extNames) > 0 {
		extsVal = strings.Join(extNames, ",")
	}
	fmt.Fprintf(&b, "build options: cgo=%s tags=%s extensions=%s\n", cgoVal, tagsVal, extsVal)

	if opts.Verbose {
		compiler := settings["-compiler"]
		if compiler == "" {
			compiler = runtime.Compiler
		}
		buildmode := settings["-buildmode"]
		if buildmode == "" {
			buildmode = "exe"
		}
		trimpath := "false"
		if settings["-trimpath"] == "true" {
			trimpath = "true"
		}
		fmt.Fprintf(&b, "compiler: %s\n", compiler)
		fmt.Fprintf(&b, "buildmode: %s\n", buildmode)
		fmt.Fprintf(&b, "trimpath: %s\n", trimpath)
		fmt.Fprintf(&b, "spi: %d\n", gvx.SPIVersion)
		for _, p := range sortedPlugins {
			summary := strings.TrimSpace(p.summary)
			if summary == "" {
				summary = "enabled"
			}
			fmt.Fprintf(&b, "extension %s: %s\n", p.name, summary)
		}
	}
	return b.String()
}

func formatVersion(info *debug.BuildInfo) string {
	return FormatVersion(info, BuildInfoOptions{})
}

func formatBuildTags(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "none"
	}
	parts := strings.Split(raw, ",")
	tags := make([]string, 0, len(parts))
	for _, part := range parts {
		if t := strings.TrimSpace(part); t != "" {
			tags = append(tags, t)
		}
	}
	if len(tags) == 0 {
		return "none"
	}
	slices.Sort(tags)
	tags = slices.Compact(tags)
	return strings.Join(tags, ",")
}

type pluginVersionInfo struct {
	name    string
	summary string
}

func sortedPluginMetadata(plugins []CLIPlugin) ([]string, []pluginVersionInfo) {
	if len(plugins) == 0 {
		return nil, nil
	}
	infos := make([]pluginVersionInfo, 0, len(plugins))
	for _, p := range plugins {
		if p == nil {
			continue
		}
		name := strings.TrimSpace(p.Name())
		if name == "" {
			continue
		}
		infos = append(infos, pluginVersionInfo{
			name:    name,
			summary: strings.TrimSpace(p.BuildSummary()),
		})
	}
	slices.SortFunc(infos, func(a, b pluginVersionInfo) int {
		return strings.Compare(a.name, b.name)
	})
	names := make([]string, 0, len(infos))
	dedup := make([]pluginVersionInfo, 0, len(infos))
	for _, item := range infos {
		if len(dedup) > 0 && dedup[len(dedup)-1].name == item.name {
			continue
		}
		dedup = append(dedup, item)
		names = append(names, item.name)
	}
	return names, dedup
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
