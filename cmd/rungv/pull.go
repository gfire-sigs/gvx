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
	fs := newImageFlagSet("pull", stderr)
	cacheFlags := addImageCacheFlags(fs)
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL that replaces the registry of the reference")

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return imageUsageError(stderr, "pull", "missing <image-or-archive> argument")
	}
	target := remaining[0]
	registryURL := strings.TrimSpace(*registryURLFlag)

	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, "pull", err)
	}

	if info, statErr := os.Stat(target); statErr == nil && !info.IsDir() {
		resolved, err := gvx.ResolveImage(ctx, cache, registryURL, target, arch)
		if err != nil {
			return imageFail(stderr, "pull", err)
		}
		layerCount := len(resolved.LayerDigests)
		if closeErr := resolved.Close(); closeErr != nil {
			return imageFail(stderr, "pull", closeErr)
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
		return imageUsageError(stderr, "pull", "%v", err)
	}

	before, _ := cache.CachedDigest(baseURL, ref.Repository, ref.ManifestReference(), arch)
	label := ref.Tag
	if ref.Digest != "" {
		label = ref.Digest
	}
	_, _ = fmt.Fprintf(stdout, "%s: Pulling from %s\n", label, ref.Repository)

	resolved, err := gvx.ResolveImage(ctx, cache, registryURL, target, arch)
	if err != nil {
		return imageFail(stderr, "pull", err)
	}
	digest := resolved.ManifestDigest
	if closeErr := resolved.Close(); closeErr != nil {
		return imageFail(stderr, "pull", closeErr)
	}
	status := "Downloaded newer image for " + ref.Familiar()
	if before != "" && before == digest {
		status = "Image is up to date for " + ref.Familiar()
	}
	_, _ = fmt.Fprintf(stdout, "Digest: %s\nStatus: %s\n%s\n", digest, status, ref.String())
	return 0
}
