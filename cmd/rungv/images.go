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
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name:    "images",
		summary: "List the images in the layer cache.\nColumns are REPOSITORY, TAG, IMAGE ID, CREATED, and SIZE.",
		usage:   []string{"rungv images [-a] [-q] [--no-trunc] [--digests] [--format json] [-cache-dir DIR] [-arch ARCH] [NAME[:TAG]]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return imagesSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// noneLabel is the placeholder for a missing repository, tag, or digest.
const noneLabel = "<none>"

// imageRow is one line of the image listing.
type imageRow struct {
	Repository string
	Tag        string
	Digest     string
	ID         string
	Created    time.Time
	Size       int64
}

// imageFilter selects the rows of one repository, and of one tag when tag is set.
type imageFilter struct {
	name string
	tag  string
}

// parseImageFilter parses the NAME argument of "images". A name without a tag
// matches every tag.
func parseImageFilter(arg string) (imageFilter, error) {
	ref, err := oci.ParseReference(arg)
	if err != nil {
		return imageFilter{}, err
	}
	f := imageFilter{name: ref.FamiliarName()}
	nameAndTag, _, _ := strings.Cut(arg, "@")
	if last := nameAndTag[strings.LastIndexByte(nameAndTag, '/')+1:]; strings.Contains(last, ":") {
		f.tag = ref.Tag
	}
	return f, nil
}

// imageRows turns images into listing rows. An image with several tags gives
// one row per tag. An image that only a digest names gives a row with the tag
// "<none>". A dangling image, which nothing names, appears only when all is set.
func imageRows(images []oci.Image, all bool, filter *imageFilter) []imageRow {
	var rows []imageRow
	for _, img := range images {
		digest := noneLabel
		if !img.FromArchive() {
			digest = img.Digest
		}
		row := imageRow{Repository: img.Name(), Digest: digest, ID: img.ID, Created: img.Created, Size: img.Size}
		tags := img.Tags
		switch {
		case len(tags) > 0:
		case img.Referenced() && img.Named():
			tags = []string{noneLabel}
		case all:
			row.Repository = noneLabel
			tags = []string{noneLabel}
		default:
			continue
		}
		for _, tag := range tags {
			r := row
			r.Tag = tag
			if filter != nil && (r.Repository != filter.name || (filter.tag != "" && r.Tag != filter.tag)) {
				continue
			}
			rows = append(rows, r)
		}
	}
	return rows
}

func imagesSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("images", stderr)
	cacheFlags := addImageCacheFlags(fs)
	var all, quiet, noTrunc, digests bool
	fs.BoolVar(&all, "a", false, "Show dangling images, which no tag or digest names")
	fs.BoolVar(&all, "all", false, "Show dangling images, which no tag or digest names")
	fs.BoolVar(&quiet, "q", false, "Print only image IDs")
	fs.BoolVar(&quiet, "quiet", false, "Print only image IDs")
	fs.BoolVar(&noTrunc, "no-trunc", false, "Print full image IDs")
	fs.BoolVar(&digests, "digests", false, "Show manifest digests")
	format := fs.String("format", "", "Output format: table (default) or json (one object per line)")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 1 {
		return imageUsageError(stderr, "images", "at most one NAME argument, got %d", fs.NArg())
	}
	if *format != "" && *format != "table" && *format != "json" {
		return imageUsageError(stderr, "images", "unsupported --format %q: use table or json", *format)
	}
	var filter *imageFilter
	if fs.NArg() == 1 {
		f, err := parseImageFilter(fs.Arg(0))
		if err != nil {
			return imageUsageError(stderr, "images", "%v", err)
		}
		filter = &f
	}

	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, "images", err)
	}
	images, err := cache.ListImages(arch)
	if err != nil {
		return imageFail(stderr, "images", err)
	}
	rows := imageRows(images, all, filter)

	displayID := func(id string) string {
		if noTrunc {
			return id
		}
		return shortImageID(id)
	}
	switch {
	case quiet:
		for _, r := range rows {
			_, _ = fmt.Fprintln(stdout, displayID(r.ID))
		}
	case *format == "json":
		enc := json.NewEncoder(stdout)
		for _, r := range rows {
			if err := enc.Encode(map[string]string{
				"ID": displayID(r.ID), "Repository": r.Repository, "Tag": r.Tag, "Digest": r.Digest,
				"CreatedAt": formatCreatedAt(r.Created), "CreatedSince": createdSince(r.Created, time.Now()),
				"Size": humanSize(r.Size),
			}); err != nil {
				return imageFail(stderr, "images", err)
			}
		}
	default:
		tw := tabwriter.NewWriter(stdout, 10, 1, 3, ' ', 0)
		header := "REPOSITORY\tTAG\t"
		if digests {
			header += "DIGEST\t"
		}
		_, _ = fmt.Fprintln(tw, header+"IMAGE ID\tCREATED\tSIZE")
		for _, r := range rows {
			line := r.Repository + "\t" + r.Tag + "\t"
			if digests {
				line += r.Digest + "\t"
			}
			_, _ = fmt.Fprintln(tw, line+displayID(r.ID)+"\t"+createdSince(r.Created, time.Now())+"\t"+humanSize(r.Size))
		}
		if err := tw.Flush(); err != nil {
			return imageFail(stderr, "images", err)
		}
	}
	return 0
}

func formatCreatedAt(created time.Time) string {
	if created.IsZero() {
		return ""
	}
	return created.UTC().Format("2006-01-02 15:04:05 -0700 MST")
}

// createdSince returns the CREATED column, such as "6 weeks ago".
func createdSince(created, now time.Time) string {
	if created.IsZero() {
		return "N/A"
	}
	return humanDuration(now.Sub(created)) + " ago"
}

// humanDuration describes d in the coarse units that Docker uses.
func humanDuration(d time.Duration) string {
	seconds := int(d.Seconds())
	switch {
	case seconds < 1:
		return "Less than a second"
	case seconds == 1:
		return "1 second"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	}
	if minutes := int(d.Minutes()); minutes == 1 {
		return "About a minute"
	} else if minutes < 60 {
		return fmt.Sprintf("%d minutes", minutes)
	}
	hours := int(d.Hours() + 0.5)
	switch {
	case hours == 1:
		return "About an hour"
	case hours < 48:
		return fmt.Sprintf("%d hours", hours)
	case hours < 24*7*2:
		return fmt.Sprintf("%d days", hours/24)
	case hours < 24*30*2:
		return fmt.Sprintf("%d weeks", hours/24/7)
	case hours < 24*365*2:
		return fmt.Sprintf("%d months", hours/24/30)
	}
	return fmt.Sprintf("%d years", int(d.Hours())/24/365)
}

// humanSize formats a byte count in decimal units with four significant
// digits, such as "7.8MB".
func humanSize(size int64) string {
	units := []string{"B", "kB", "MB", "GB", "TB", "PB"}
	value := float64(size)
	i := 0
	for value >= 1000 && i < len(units)-1 {
		value /= 1000
		i++
	}
	return fmt.Sprintf("%.4g%s", value, units[i])
}
