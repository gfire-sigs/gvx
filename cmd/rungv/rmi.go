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

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name: "rmi",
		summary: "Remove images from the layer cache.\n" +
			"A name removes one tag. An image ID with several tags needs -f.\n" +
			"The command deletes layer files that no other image uses.",
		usage: []string{"rungv rmi [-f] [-cache-dir DIR] [-arch ARCH] IMAGE..."},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return rmiSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// imageNotFound turns a store lookup error into the message of a command.
func imageNotFound(query string, err error) error {
	if errors.Is(err, oci.ErrNotCached) {
		return fmt.Errorf("no such image: %s", query)
	}
	if errors.Is(err, oci.ErrAmbiguousImage) {
		return fmt.Errorf("the ID prefix %q matches several images: use more digits", query)
	}
	return err
}

func rmiSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("rmi", stderr)
	cacheFlags := addImageCacheFlags(fs)
	var force bool
	fs.BoolVar(&force, "f", false, "Remove an image ID that has several tags")
	fs.BoolVar(&force, "force", false, "Remove an image ID that has several tags")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return imageUsageError(stderr, "rmi", "missing IMAGE argument")
	}
	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, "rmi", err)
	}

	code := 0
	for _, query := range fs.Args() {
		report, err := removeImage(cache, query, arch, force)
		for _, name := range report.Untagged {
			_, _ = fmt.Fprintf(stdout, "Untagged: %s\n", name)
		}
		for _, id := range report.Deleted {
			_, _ = fmt.Fprintf(stdout, "Deleted: %s\n", id)
		}
		if err != nil {
			code = imageFail(stderr, "rmi", err)
		}
	}
	return code
}

// removeImage removes the image that query names. A tag name removes that tag
// and, when no other name remains, the image. An image ID, a manifest digest, or
// name@digest removes every name of the image.
func removeImage(cache *oci.LayerCache, query, arch string, force bool) (oci.RemoveReport, error) {
	sel, err := cache.Select(query, arch)
	if err != nil {
		return oci.RemoveReport{}, imageNotFound(query, err)
	}
	if sel.Ref != nil && sel.Ref.Digest == "" {
		return cache.Untag(sel.Images[0], sel.Ref.Tag)
	}

	if sel.Ref == nil && !force {
		tags := 0
		for _, img := range sel.Images {
			tags += len(img.Tags)
		}
		if tags > 1 {
			return oci.RemoveReport{}, fmt.Errorf("conflict: unable to delete %s (must be forced) - image is referenced in multiple repositories",
				shortImageID(sel.Images[0].ID))
		}
	}
	var total oci.RemoveReport
	var errs []error
	for _, img := range sel.Images {
		report, err := cache.Remove(img)
		total.Untagged = append(total.Untagged, report.Untagged...)
		total.Deleted = append(total.Deleted, report.Deleted...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return total, errors.Join(errs...)
}
