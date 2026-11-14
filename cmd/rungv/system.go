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
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name:    "system",
		summary: "Inspect host backends, disk usage, and prune unused storage (info, df, prune).",
		usage:   []string{"rungv system <info|df|prune> [flags]"},
		run:     systemGroupSubcommand,
	})
	register(command{
		name:    "info",
		summary: "Display host system, execution backend, and cache directory information.",
		usage:   []string{"rungv info [-f|--format json|TEMPLATE] [-cache-dir DIR]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return systemInfoSubcommand(ctx, "info", args, streams.stdout, streams.stderr)
		},
	})
}

func systemGroupSubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 {
		printSystemGroupUsage(streams.stderr)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "-h", "--help", "help":
		printSystemGroupUsage(streams.stdout)
		return 0
	case "info":
		return systemInfoSubcommand(ctx, "system info", rest, streams.stdout, streams.stderr)
	case "df":
		return systemDFSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "prune":
		return systemPruneSubcommand(ctx, rest, streams)
	default:
		_, _ = fmt.Fprintf(streams.stderr, "rungv system: unknown subcommand %q\n", sub)
		printSystemGroupUsage(streams.stderr)
		return 2
	}
}

func printSystemGroupUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: rungv system <subcommand> [flags]")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Subcommands:")
	_, _ = fmt.Fprintln(w, "  info        Display host environment, available backends, and storage paths")
	_, _ = fmt.Fprintln(w, "  df          Show image and local volume disk usage")
	_, _ = fmt.Fprintln(w, "  prune       Remove unused images and optional local volumes")
}

func systemInfoSubcommand(_ context.Context, cmdName string, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet(cmdName, stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS layer cache directory")
	tune := addTuneFlags(fs)
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if spec := strings.TrimSpace(format); spec != "" && spec != "table" && spec != "json" {
		if _, _, err := compileFormatTemplate(spec); err != nil {
			return imageUsageError(stderr, cmdName, "invalid --format %q: %v", format, err)
		}
	}

	tuned, err := tune.values()
	if err != nil {
		return imageUsageError(stderr, cmdName, "%v", err)
	}
	info, err := gvx.ProbeSystemInfo(*cacheDir, tuned)
	if err != nil {
		return imageFail(stderr, cmdName, err)
	}

	usageErr, writeErr := renderSingleFormat(stdout, format, info, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 18, 1, 2, ' ', 0)
		backends := "none"
		if len(info.AvailableBackends) > 0 {
			backends = strings.Join(info.AvailableBackends, ", ")
		}
		_, _ = fmt.Fprintf(tw, "OS/Arch:\t%s/%s\n", info.OS, info.Architecture)
		_, _ = fmt.Fprintf(tw, "Go Version:\t%s\n", info.GoVersion)
		_, _ = fmt.Fprintf(tw, "CPUs:\t%d\n", info.NumCPU)
		_, _ = fmt.Fprintf(tw, "Page Size:\t%d B\n", info.PageSize)
		_, _ = fmt.Fprintf(tw, "Default Backend:\t%s\n", info.DefaultBackend)
		_, _ = fmt.Fprintf(tw, "Available Backends:\t%s\n", backends)
		_, _ = fmt.Fprintf(tw, "Host Lockdown:\t%s\n", info.HostLockdown)
		_, _ = fmt.Fprintf(tw, "Layer Cache Dir:\t%s\n", info.LayerCacheDir)
		_, _ = fmt.Fprintf(tw, "Volume Dir:\t%s\n", info.VolumeDir)
		_, _ = fmt.Fprintf(tw, "Images:\t%d\n", info.Images)
		_, _ = fmt.Fprintf(tw, "Volumes:\t%d\n", info.Volumes)
		if err := tw.Flush(); err != nil {
			return err
		}
		for _, warn := range info.BackendWarnings {
			if _, err := fmt.Fprintf(w, "WARNING: %s\n", warn); err != nil {
				return err
			}
		}
		return nil
	})
	if usageErr != nil {
		return imageUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return imageFail(stderr, cmdName, writeErr)
	}
	return 0
}

type systemDFRow struct {
	Type        string `json:"Type"`
	TotalCount  int    `json:"TotalCount"`
	Active      int    `json:"Active"`
	Size        string `json:"Size"`
	Reclaimable string `json:"Reclaimable"`
}

func formatReclaimable(reclaimable, total int64) string {
	if reclaimable <= 0 || total <= 0 {
		return "0B"
	}
	pct := (reclaimable * 100) / total
	return fmt.Sprintf("%s (%d%%)", humanSize(reclaimable), pct)
}

func systemDFSubcommand(_ context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "system df"
	fs := newImageFlagSet(cmdName, stderr)
	cacheDir := fs.String("cache-dir", "", "EROFS layer cache directory")
	tune := addTuneFlags(fs)
	var verbose bool
	fs.BoolVar(&verbose, "v", false, "Show detailed per-image and per-volume space usage")
	fs.BoolVar(&verbose, "verbose", false, "Show detailed per-image and per-volume space usage")
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

	tuned, err := tune.values()
	if err != nil {
		return imageUsageError(stderr, cmdName, "%v", err)
	}
	resolvedDir := strings.TrimSpace(*cacheDir)
	if resolvedDir == "" {
		resolvedDir, err = oci.DefaultCacheDir()
		if err != nil {
			return imageFail(stderr, cmdName, err)
		}
	}

	var imgDU oci.CacheDiskUsage
	var cache *oci.LayerCache
	if st, statErr := os.Stat(resolvedDir); statErr == nil && st.IsDir() {
		cache, err = gvx.NewLayerCacheWithTuning(resolvedDir, tuned)
		if err != nil {
			return imageFail(stderr, cmdName, err)
		}
		imgDU, err = cache.DiskUsage()
		if err != nil {
			return imageFail(stderr, cmdName, err)
		}
	}

	volDU, err := gvx.ComputeVolumeDiskUsage(*cacheDir)
	if err != nil {
		return imageFail(stderr, cmdName, err)
	}

	rows := []systemDFRow{
		{
			Type:        "Images",
			TotalCount:  imgDU.TotalImages,
			Active:      imgDU.ActiveImages,
			Size:        humanSize(imgDU.TotalBytes),
			Reclaimable: formatReclaimable(imgDU.ReclaimableBytes, imgDU.TotalBytes),
		},
		{
			Type:        "Local Volumes",
			TotalCount:  volDU.Total,
			Active:      volDU.Active,
			Size:        humanSize(volDU.TotalBytes),
			Reclaimable: formatReclaimable(volDU.ReclaimableBytes, volDU.TotalBytes),
		},
	}

	usageErr, writeErr := renderListFormat(stdout, *format, rows, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TYPE\tTOTAL\tACTIVE\tSIZE\tRECLAIMABLE")
		for _, r := range rows {
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\n", r.Type, r.TotalCount, r.Active, r.Size, r.Reclaimable)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if !verbose {
			return nil
		}
		return writeVerboseSystemDF(w, cache, *cacheDir)
	})
	if usageErr != nil {
		return imageUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return imageFail(stderr, cmdName, writeErr)
	}
	return 0
}

func writeVerboseSystemDF(w io.Writer, cache *oci.LayerCache, cacheDir string) error {
	now := time.Now()
	_, _ = fmt.Fprintln(w, "\nImages space usage:")
	itw := tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
	_, _ = fmt.Fprintln(itw, "REPOSITORY\tTAG\tARCH\tIMAGE ID\tCREATED\tSIZE")
	if cache != nil {
		for _, arch := range []string{"amd64", "arm64"} {
			imgs, err := cache.ListImages(arch)
			if err != nil {
				return err
			}
			for _, r := range imageRows(imgs, true, nil) {
				_, _ = fmt.Fprintf(itw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.Repository, r.Tag, arch, shortImageID(r.ID), createdSince(r.Created, now), humanSize(r.Size))
			}
		}
	}
	if err := itw.Flush(); err != nil {
		return err
	}

	vols, err := gvx.ListVolumes(cacheDir)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(w, "\nLocal Volumes space usage:")
	vtw := tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
	_, _ = fmt.Fprintln(vtw, "VOLUME NAME\tDRIVER\tIN USE\tSIZE")
	for _, v := range vols {
		_, _ = fmt.Fprintf(vtw, "%s\t%s\t%t\t%s\n", v.Name, v.Driver, v.InUse, humanSize(v.SizeBytes))
	}
	return vtw.Flush()
}

func systemPruneSubcommand(_ context.Context, args []string, streams cliIO) int {
	const cmdName = "system prune"
	fs := newImageFlagSet(cmdName, streams.stderr)
	cacheFlags := addImageCacheFlags(fs)
	var all, pruneVolumes, force bool
	fs.BoolVar(&all, "a", false, "Remove all cached images, not only dangling images")
	fs.BoolVar(&all, "all", false, "Remove all cached images, not only dangling images")
	fs.BoolVar(&pruneVolumes, "volumes", false, "Prune unlocked local volumes")
	fs.BoolVar(&force, "f", false, "Do not prompt for confirmation")
	fs.BoolVar(&force, "force", false, "Do not prompt for confirmation")

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(streams.stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	targets := []string{"dangling images"}
	if all {
		targets = []string{"all cached images for the selected architecture"}
	}
	if pruneVolumes {
		targets = append(targets, "all unlocked local volumes")
	}
	warning := "This will remove " + strings.Join(targets, " and ") + "."
	confirmed, err := confirmPrune(streams.stdin, streams.stdout, force, warning)
	if err != nil {
		return imageFail(streams.stderr, cmdName, err)
	}
	if !confirmed {
		return 0
	}

	var totalReclaimed int64
	code := 0

	resolvedDir := strings.TrimSpace(*cacheFlags.cacheDir)
	if resolvedDir == "" {
		resolvedDir, err = oci.DefaultCacheDir()
		if err != nil {
			return imageFail(streams.stderr, cmdName, err)
		}
	}
	if st, statErr := os.Stat(resolvedDir); statErr == nil && st.IsDir() {
		cache, arch, openErr := cacheFlags.open()
		if openErr != nil {
			code = imageFail(streams.stderr, cmdName, openErr)
		} else {
			imgReport, pruneErr := cache.PruneImages(oci.PruneOptions{Arch: arch, All: all})
			writeImagePruneReport(streams.stdout, imgReport)
			totalReclaimed += imgReport.SpaceReclaimed
			if pruneErr != nil {
				code = imageFail(streams.stderr, cmdName, pruneErr)
			}
		}
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		code = imageFail(streams.stderr, cmdName, statErr)
	}

	if pruneVolumes {
		volReport, volErr := gvx.PruneVolumes(*cacheFlags.cacheDir)
		writeVolumePruneReport(streams.stdout, volReport)
		totalReclaimed += volReport.SpaceReclaimed
		if volErr != nil {
			code = imageFail(streams.stderr, cmdName, volErr)
		}
	}

	_, _ = fmt.Fprintf(streams.stdout, "Total reclaimed space: %s\n", humanSize(totalReclaimed))
	return code
}
