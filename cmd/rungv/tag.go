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
	"io"

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name:    "tag",
		summary: "Give an image another name.\nThe target can name another repository or registry.",
		usage:   []string{"rungv tag [-cache-dir DIR] [-arch ARCH] SOURCE TARGET"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return tagSubcommand(ctx, args, streams.stderr)
		},
	})
}

func tagSubcommand(_ context.Context, args []string, stderr io.Writer) int {
	fs := newImageFlagSet("tag", stderr)
	cacheFlags := addImageCacheFlags(fs)
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 2 {
		return imageUsageError(stderr, "tag", "want SOURCE and TARGET arguments, got %d", fs.NArg())
	}
	source, targetName := fs.Arg(0), fs.Arg(1)
	target, err := oci.ParseReference(targetName)
	if err != nil {
		return imageUsageError(stderr, "tag", "%v", err)
	}
	if target.Digest != "" {
		return imageUsageError(stderr, "tag", "the target %q must not have a digest", targetName)
	}

	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, "tag", err)
	}
	sel, err := cache.Select(source, arch)
	if err != nil {
		return imageFail(stderr, "tag", imageNotFound(source, err))
	}
	if err := cache.Tag(sel.Images[0], target); err != nil {
		return imageFail(stderr, "tag", err)
	}
	return 0
}
