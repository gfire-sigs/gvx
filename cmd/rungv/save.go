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
	"path/filepath"

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name: "save",
		summary: "Write images to a tar archive that is an OCI image layout and a docker save archive.\n" +
			"The command fetches the original layer blobs from the registry that the image came from.\n" +
			"An image that came from an archive has no registry source and cannot be saved.",
		usage: []string{"rungv save [-o FILE] [-cache-dir DIR] [-arch ARCH] IMAGE..."},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return saveSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

func saveSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet("save", stderr)
	cacheFlags := addImageCacheFlags(fs)
	var output string
	fs.StringVar(&output, "o", "", "Write the archive to FILE instead of standard output")
	fs.StringVar(&output, "output", "", "Write the archive to FILE instead of standard output")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return imageUsageError(stderr, "save", "missing IMAGE argument")
	}
	if output == "" && oci.IsTerminal(stdout) {
		return imageUsageError(stderr, "save", "refusing to write an archive to a terminal: use -o FILE or redirect standard output")
	}
	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, "save", err)
	}

	var targets []oci.SaveTarget
	for _, query := range fs.Args() {
		sel, err := cache.Select(query, arch)
		if err != nil {
			return imageFail(stderr, "save", imageNotFound(query, err))
		}
		target := oci.SaveTarget{Image: sel.Images[0]}
		if sel.Ref != nil && sel.Ref.Tag != "" {
			name := *sel.Ref
			name.Digest = ""
			target.Names = []oci.Reference{name}
		}
		targets = append(targets, target)
	}

	if err := saveArchive(ctx, cache, targets, output, stdout); err != nil {
		return imageFail(stderr, "save", err)
	}
	return 0
}

// saveArchive writes the archive to a temporary file first. A failure removes
// the file, so that no partial archive reaches output or stdout. On success it
// renames the file to output, or copies it to stdout when output is empty.
func saveArchive(ctx context.Context, cache *oci.LayerCache, targets []oci.SaveTarget, output string, stdout io.Writer) (err error) {
	dir := os.TempDir()
	if output != "" {
		dir = filepath.Dir(output)
	}
	tmp, err := os.CreateTemp(dir, ".rungv-save-*.tmp")
	if err != nil {
		return fmt.Errorf("create a temporary archive file: %w", err)
	}
	closed := false
	defer func() {
		if err == nil && output != "" {
			return // the rename published the file
		}
		if !closed {
			err = errors.Join(err, tmp.Close())
		}
		err = errors.Join(err, removeIfExists(tmp.Name()))
	}()

	if err := cache.SaveImages(ctx, tmp, nil, targets); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmp.Name(), err)
	}
	if output == "" {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind %s: %w", tmp.Name(), err)
		}
		if _, err := io.Copy(stdout, tmp); err != nil {
			return fmt.Errorf("write the archive: %w", err)
		}
		return nil
	}
	closed = true
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("set the mode of %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), output); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
	}
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
