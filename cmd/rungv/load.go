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
	"os"

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name: "load",
		summary: "Load images from an OCI image layout or docker save archive.\n" +
			"The archive can be gzip or zstd compressed. The command reads standard input without -i.",
		usage: []string{"rungv load [-i FILE] [-q] [-cache-dir DIR] [-arch ARCH]"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return loadSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
}

func loadSubcommand(_ context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	fs := newImageFlagSet("load", stderr)
	cacheFlags := addImageCacheFlags(fs)
	var input string
	var quiet bool
	fs.StringVar(&input, "i", "", "Read the archive from FILE instead of standard input")
	fs.StringVar(&input, "input", "", "Read the archive from FILE instead of standard input")
	fs.BoolVar(&quiet, "q", false, "Suppress the output")
	fs.BoolVar(&quiet, "quiet", false, "Suppress the output")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 0 {
		return imageUsageError(stderr, "load", "unexpected argument %q", fs.Arg(0))
	}

	var source io.Reader = stdin
	if input != "" {
		f, err := os.Open(input)
		if err != nil {
			return imageFail(stderr, "load", err)
		}
		defer func() {
			if err := f.Close(); err != nil && code == 0 {
				code = imageFail(stderr, "load", err)
			}
		}()
		source = f
	} else if stdin == nil || oci.IsTerminal(stdin) {
		return imageUsageError(stderr, "load", "no archive on standard input: use -i FILE or pipe an archive")
	}

	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, "load", err)
	}
	images, err := oci.LoadArchive(source, cache, arch)
	if err != nil {
		return imageFail(stderr, "load", err)
	}
	if quiet {
		return 0
	}
	for _, img := range images {
		if len(img.Names) == 0 {
			_, _ = fmt.Fprintf(stdout, "Loaded image ID: %s\n", img.ID)
			continue
		}
		for _, name := range img.Names {
			_, _ = fmt.Fprintf(stdout, "Loaded image: %s\n", name.Familiar())
		}
	}
	return 0
}
