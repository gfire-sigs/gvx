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
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name: "pull",
		summary: "Download an OCI image into the EROFS layer cache.\n" +
			"The argument is a Docker image reference or an image archive file.\n" +
			"The reference names its registry, as in ghcr.io/org/img:v1 or name@sha256:...",
		usage: []string{"rungv pull [flags] <image-or-archive>"},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return pullSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func pullSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rungv pull", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL that replaces the registry of the reference")
	archFlag := fs.String("arch", runtime.GOARCH, "Target Linux architecture (amd64 or arm64)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		_, _ = fmt.Fprintln(stderr, "rungv pull: missing <image-or-archive> argument")
		return 2
	}
	target := remaining[0]
	registryURL := strings.TrimSpace(*registryURLFlag)

	cache, err := gvx.NewLayerCache(strings.TrimSpace(*cacheDirFlag))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", err)
		return 1
	}

	if info, statErr := os.Stat(target); statErr == nil && !info.IsDir() {
		resolved, err := gvx.ResolveImage(ctx, cache, registryURL, target, *archFlag)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", err)
			return 1
		}
		layerCount := len(resolved.LayerDigests)
		if closeErr := resolved.Close(); closeErr != nil {
			_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", closeErr)
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "pulled %s (%d EROFS layers cached in %s)\n", target, layerCount, cache.Dir())
		return 0
	}

	var ref oci.Reference
	baseURL := registryURL
	if registryURL != "" {
		ref, err = oci.ParseReferenceAt(target, registryURL)
	} else {
		ref, err = oci.ParseReference(target)
		baseURL = ref.BaseURL()
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", err)
		return 2
	}

	before, _ := cache.CachedDigest(baseURL, ref.Repository, ref.ManifestReference(), *archFlag)
	label := ref.Tag
	if ref.Digest != "" {
		label = ref.Digest
	}
	_, _ = fmt.Fprintf(stdout, "%s: Pulling from %s\n", label, ref.Repository)

	resolved, err := gvx.ResolveImage(ctx, cache, registryURL, target, *archFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", err)
		return 1
	}
	digest := resolved.ManifestDigest
	if closeErr := resolved.Close(); closeErr != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", closeErr)
		return 1
	}
	status := "Downloaded newer image for " + ref.Familiar()
	if before != "" && before == digest {
		status = "Image is up to date for " + ref.Familiar()
	}
	_, _ = fmt.Fprintf(stdout, "Digest: %s\nStatus: %s\n%s\n", digest, status, ref.String())
	return 0
}
