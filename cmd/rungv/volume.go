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
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "volume",
		summary: "Manage named local volumes (create, ls, inspect, rm, prune).",
		usage:   []string{"rungv volume <create|ls|inspect|rm|prune> [flags] [args...]"},
		run:     volumeGroupSubcommand,
	})
}

func volumeGroupSubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 {
		printVolumeGroupUsage(streams.stderr)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "-h", "--help", "help":
		printVolumeGroupUsage(streams.stdout)
		return 0
	case "create":
		return volumeCreateSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "ls", "list":
		return volumeListSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "inspect":
		return volumeInspectSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "rm", "remove":
		return volumeRemoveSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "prune":
		return volumePruneSubcommand(ctx, rest, streams)
	default:
		_, _ = fmt.Fprintf(streams.stderr, "rungv volume: unknown subcommand %q\n", sub)
		printVolumeGroupUsage(streams.stderr)
		return 2
	}
}

func printVolumeGroupUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: rungv volume <subcommand> [flags] [args...]")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Subcommands:")
	_, _ = fmt.Fprintln(w, "  create      Create a named volume (ext4lite or hostfs)")
	_, _ = fmt.Fprintln(w, "  ls, list    List named volumes")
	_, _ = fmt.Fprintln(w, "  inspect     Print detailed metadata for one or more volumes")
	_, _ = fmt.Fprintln(w, "  rm, remove  Remove one or more unlocked volumes")
	_, _ = fmt.Fprintln(w, "  prune       Remove all unlocked local volumes")
}

func volumeCreateSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "volume create"
	fs := newImageFlagSet(cmdName, stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS cache parent directory")
	var driver string
	registerAlias([]string{"d", "driver"}, func(n string) {
		fs.StringVar(&driver, n, string(gvx.DriverExt4lite), "Volume driver (ext4lite or hostfs)")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 1 {
		return imageUsageError(stderr, cmdName, "at most one VOLUME argument, got %d", fs.NArg())
	}
	var name string
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	vi, err := gvx.CreateVolume(*cacheDir, name, gvx.MountDriver(strings.TrimSpace(driver)))
	if err != nil {
		if errors.Is(err, gvx.ErrInvalidConfig) {
			return imageUsageError(stderr, cmdName, "%v", err)
		}
		return imageFail(stderr, cmdName, err)
	}
	_, _ = fmt.Fprintln(stdout, vi.Name)
	return 0
}

type volumeFormatRow struct {
	Driver     string `json:"Driver"`
	Name       string `json:"Name"`
	Mountpoint string `json:"Mountpoint"`
	CreatedAt  string `json:"CreatedAt"`
	Size       string `json:"Size"`
	InUse      bool   `json:"InUse"`
}

func volumeListSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "volume ls"
	fs := newImageFlagSet(cmdName, stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS cache parent directory")
	var quiet bool
	fs.BoolVar(&quiet, "q", false, "Print only volume names")
	fs.BoolVar(&quiet, "quiet", false, "Print only volume names")
	format := fs.String("format", "", "Output format: table (default), json, or a Go template")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if spec := strings.TrimSpace(*format); spec != "" && spec != "table" && spec != "json" {
		if _, _, err := compileFormatTemplate(spec); err != nil {
			return imageUsageError(stderr, cmdName, "invalid --format %q: %v", *format, err)
		}
	}

	vols, err := gvx.ListVolumes(*cacheDir)
	if err != nil {
		return imageFail(stderr, cmdName, err)
	}
	if quiet {
		for _, v := range vols {
			_, _ = fmt.Fprintln(stdout, v.Name)
		}
		return 0
	}

	rows := make([]volumeFormatRow, 0, len(vols))
	for _, v := range vols {
		rows = append(rows, volumeFormatRow{
			Driver:     string(v.Driver),
			Name:       v.Name,
			Mountpoint: v.Mountpoint,
			CreatedAt:  formatCreatedAt(v.CreatedAt),
			Size:       humanSize(v.SizeBytes),
			InUse:      v.InUse,
		})
	}
	usageErr, writeErr := renderListFormat(stdout, *format, rows, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
		_, _ = fmt.Fprintln(tw, "DRIVER\tVOLUME NAME")
		for _, r := range rows {
			_, _ = fmt.Fprintf(tw, "%s\t%s\n", r.Driver, r.Name)
		}
		return tw.Flush()
	})
	if usageErr != nil {
		return imageUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return imageFail(stderr, cmdName, writeErr)
	}
	return 0
}

func volumeInspectSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "volume inspect"
	fs := newImageFlagSet(cmdName, stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS cache parent directory")
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using json (default) or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return imageUsageError(stderr, cmdName, "missing VOLUME argument")
	}
	if spec := strings.TrimSpace(format); spec != "" && spec != "json" {
		tmpl, _, err := compileFormatTemplate(spec)
		if err != nil {
			return imageUsageError(stderr, cmdName, "invalid --format %q: %v", format, err)
		}
		if tmpl == nil {
			return imageUsageError(stderr, cmdName, "invalid --format %q: table requires a Go template expression", format)
		}
	}

	code := 0
	items := []gvx.VolumeInfo{}
	for _, name := range fs.Args() {
		vi, err := gvx.InspectVolume(*cacheDir, name)
		if err != nil {
			if errors.Is(err, gvx.ErrVolumeNotFound) {
				code = imageFail(stderr, cmdName, fmt.Errorf("no such volume: %s", name))
			} else {
				code = imageFail(stderr, cmdName, err)
			}
			continue
		}
		items = append(items, vi)
	}
	if len(items) == 0 && code != 0 && strings.TrimSpace(format) != "" && strings.TrimSpace(format) != "json" {
		return code
	}
	usageErr, writeErr := renderInspectFormat(stdout, format, items)
	if usageErr != nil {
		return imageUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return imageFail(stderr, cmdName, writeErr)
	}
	return code
}

func volumeRemoveSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "volume rm"
	fs := newImageFlagSet(cmdName, stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS cache parent directory")
	var force bool
	fs.BoolVar(&force, "f", false, "Ignore nonexistent volumes")
	fs.BoolVar(&force, "force", false, "Ignore nonexistent volumes")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return imageUsageError(stderr, cmdName, "missing VOLUME argument")
	}

	code := 0
	for _, name := range fs.Args() {
		err := gvx.RemoveVolume(*cacheDir, name)
		if err == nil {
			_, _ = fmt.Fprintln(stdout, name)
			continue
		}
		if force && errors.Is(err, gvx.ErrVolumeNotFound) {
			continue
		}
		if errors.Is(err, gvx.ErrVolumeNotFound) {
			code = imageFail(stderr, cmdName, fmt.Errorf("no such volume: %s", name))
			continue
		}
		code = imageFail(stderr, cmdName, err)
	}
	return code
}

func volumePruneSubcommand(_ context.Context, args []string, streams cliIO) int {
	const cmdName = "volume prune"
	fs := newImageFlagSet(cmdName, streams.stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS cache parent directory")
	var force bool
	fs.BoolVar(&force, "f", false, "Do not prompt for confirmation")
	fs.BoolVar(&force, "force", false, "Do not prompt for confirmation")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(streams.stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	confirmed, err := confirmPrune(streams.stdin, streams.stdout, force, "This will remove all local volumes not locked by a running sandbox.")
	if err != nil {
		return imageFail(streams.stderr, cmdName, err)
	}
	if !confirmed {
		return 0
	}

	report, err := gvx.PruneVolumes(*cacheDir)
	writeVolumePruneReport(streams.stdout, report)
	if err != nil {
		return imageFail(streams.stderr, cmdName, err)
	}
	_, _ = fmt.Fprintf(streams.stdout, "Total reclaimed space: %s\n", humanSize(report.SpaceReclaimed))
	return 0
}

func writeVolumePruneReport(w io.Writer, report gvx.VolumePruneReport) {
	if len(report.Deleted) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "Deleted Volumes:")
	for _, name := range report.Deleted {
		_, _ = fmt.Fprintln(w, name)
	}
	_, _ = fmt.Fprintln(w, "")
}
