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

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name:    "image",
		summary: "Manage cached OCI images (ls, pull, rm, inspect, tag, save, load, prune).",
		usage:   []string{"rungv image <ls|pull|rm|inspect|tag|save|load|prune> [flags] [args...]"},
		run:     imageGroupSubcommand,
	})
}

func imageGroupSubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 {
		printImageGroupUsage(streams.stderr)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "-h", "--help", "help":
		printImageGroupUsage(streams.stdout)
		return 0
	case "ls", "list":
		return runImagesCommand(ctx, "image ls", rest, streams.stdout, streams.stderr)
	case "pull":
		return pullSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "rm", "remove", "rmi":
		return rmiSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "inspect":
		return runInspectCommand(ctx, "image inspect", rest, streams.stdout, streams.stderr)
	case "tag":
		return tagSubcommand(ctx, rest, streams.stderr)
	case "save":
		return saveSubcommand(ctx, rest, streams.stdout, streams.stderr)
	case "load":
		return loadSubcommand(ctx, rest, streams.stdin, streams.stdout, streams.stderr)
	case "prune":
		return imagePruneSubcommand(ctx, rest, streams)
	default:
		_, _ = fmt.Fprintf(streams.stderr, "rungv image: unknown subcommand %q\n", sub)
		printImageGroupUsage(streams.stderr)
		return 2
	}
}

func printImageGroupUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: rungv image <subcommand> [flags] [args...]")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Subcommands:")
	_, _ = fmt.Fprintln(w, "  ls, list    List cached images")
	_, _ = fmt.Fprintln(w, "  pull        Download an OCI image into the EROFS layer cache")
	_, _ = fmt.Fprintln(w, "  rm, rmi     Remove one or more cached images")
	_, _ = fmt.Fprintln(w, "  inspect     Print detailed metadata for one or more images")
	_, _ = fmt.Fprintln(w, "  tag         Create a tag TARGET that refers to SOURCE")
	_, _ = fmt.Fprintln(w, "  save        Write one or more images to a tar archive")
	_, _ = fmt.Fprintln(w, "  load        Load images from a tar archive")
	_, _ = fmt.Fprintln(w, "  prune       Remove dangling or unused images from the layer cache")
}

func imagePruneSubcommand(_ context.Context, args []string, streams cliIO) int {
	const cmdName = "image prune"
	fs := newImageFlagSet(cmdName, streams.stderr)
	cacheFlags := addImageCacheFlags(fs)
	platformFlag := fs.String("platform", "", "Target image platform (linux/amd64 or linux/arm64)")
	var all, force bool
	fs.BoolVar(&all, "a", false, "Remove all cached images, not only dangling images")
	fs.BoolVar(&all, "all", false, "Remove all cached images, not only dangling images")
	fs.BoolVar(&force, "f", false, "Do not prompt for confirmation")
	fs.BoolVar(&force, "force", false, "Do not prompt for confirmation")

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(streams.stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}
	if p := strings.TrimSpace(*platformFlag); p != "" {
		platArch, err := parseImagePlatformArch(p)
		if err != nil {
			return imageUsageError(streams.stderr, cmdName, "--platform: %v", err)
		}
		*cacheFlags.arch = platArch
	}

	warning := "This will remove all dangling images."
	if all {
		warning = "This will remove all cached images for the selected architecture."
	}
	confirmed, err := confirmPrune(streams.stdin, streams.stdout, force, warning)
	if err != nil {
		return imageFail(streams.stderr, cmdName, err)
	}
	if !confirmed {
		return 0
	}

	resolvedDir := strings.TrimSpace(*cacheFlags.cacheDir)
	if resolvedDir == "" {
		resolvedDir, err = oci.DefaultCacheDir()
		if err != nil {
			return imageFail(streams.stderr, cmdName, err)
		}
	}
	if st, statErr := os.Stat(resolvedDir); errors.Is(statErr, os.ErrNotExist) || (statErr == nil && !st.IsDir()) {
		_, _ = fmt.Fprintln(streams.stdout, "Total reclaimed space: 0B")
		return 0
	}

	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(streams.stderr, cmdName, err)
	}
	report, err := cache.PruneImages(oci.PruneOptions{Arch: arch, All: all})
	writeImagePruneReport(streams.stdout, report)
	if err != nil {
		return imageFail(streams.stderr, cmdName, err)
	}
	_, _ = fmt.Fprintf(streams.stdout, "Total reclaimed space: %s\n", humanSize(report.SpaceReclaimed))
	return 0
}

func writeImagePruneReport(w io.Writer, report oci.PruneReport) {
	if len(report.Untagged) == 0 && len(report.Deleted) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "Deleted Images:")
	for _, u := range report.Untagged {
		_, _ = fmt.Fprintf(w, "untagged: %s\n", u)
	}
	for _, d := range report.Deleted {
		_, _ = fmt.Fprintf(w, "deleted: %s\n", d)
	}
	_, _ = fmt.Fprintln(w, "")
}
