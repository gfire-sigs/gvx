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
	"slices"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/oci"
)

func init() {
	register(command{
		name:    "inspect",
		summary: "Print the details of cached images as a JSON array or Go template.\nThe fields follow docker image inspect.",
		usage:   []string{"rungv inspect [-f|--format TEMPLATE] [-cache-dir DIR] [-arch ARCH] IMAGE..."},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return inspectSubcommand(ctx, args, streams.stdout, streams.stderr)
		},
	})
}

// inspectConfig is the Config object of the inspect output.
type inspectConfig struct {
	Env          []string            `json:"Env"`
	Cmd          []string            `json:"Cmd"`
	Entrypoint   []string            `json:"Entrypoint"`
	WorkingDir   string              `json:"WorkingDir"`
	User         string              `json:"User"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
}

// inspectRootFS is the RootFS object of the inspect output.
type inspectRootFS struct {
	Type   string   `json:"Type"`
	Layers []string `json:"Layers"`
}

// inspectOutput is one element of the inspect array.
type inspectOutput struct {
	ID           string        `json:"Id"`
	RepoTags     []string      `json:"RepoTags"`
	RepoDigests  []string      `json:"RepoDigests"`
	Created      time.Time     `json:"Created"`
	Architecture string        `json:"Architecture"`
	Os           string        `json:"Os"`
	Config       inspectConfig `json:"Config"`
	RootFS       inspectRootFS `json:"RootFS"`
	Size         int64         `json:"Size"`
}

// newInspectOutput describes the image with the names of every record that
// shares its ID.
func newInspectOutput(img oci.Image, sameID []oci.Image) inspectOutput {
	out := inspectOutput{
		ID: img.ID, RepoTags: []string{}, RepoDigests: []string{},
		Created: img.Created, Architecture: img.Architecture, Os: img.OS,
		Config: inspectConfig{
			Env: nonNil(img.Config.Env), Cmd: nonNil(img.Config.Cmd), Entrypoint: nonNil(img.Config.Entrypoint),
			WorkingDir: img.Config.WorkingDir, User: img.Config.User, ExposedPorts: img.Config.ExposedPorts,
		},
		RootFS: inspectRootFS{Type: "layers", Layers: nonNil(img.DiffIDs)},
		Size:   img.Size,
	}
	if out.Os == "" {
		out.Os = "linux"
	}
	for _, other := range sameID {
		for _, tag := range other.RepoTags() {
			if !slices.Contains(out.RepoTags, tag) {
				out.RepoTags = append(out.RepoTags, tag)
			}
		}
		for _, d := range other.RepoDigests() {
			if !slices.Contains(out.RepoDigests, d) {
				out.RepoDigests = append(out.RepoDigests, d)
			}
		}
	}
	slices.Sort(out.RepoTags)
	slices.Sort(out.RepoDigests)
	return out
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func inspectSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runInspectCommand(ctx, "inspect", args, stdout, stderr)
}

func runInspectCommand(_ context.Context, cmdName string, args []string, stdout, stderr io.Writer) int {
	fs := newImageFlagSet(cmdName, stderr)
	cacheFlags := addImageCacheFlags(fs)
	var format string
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using json (default) or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return imageUsageError(stderr, cmdName, "missing IMAGE argument")
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
	cache, arch, err := cacheFlags.open()
	if err != nil {
		return imageFail(stderr, cmdName, err)
	}
	all, err := cache.ListImages(arch)
	if err != nil {
		return imageFail(stderr, cmdName, err)
	}

	code := 0
	outputs := []inspectOutput{}
	for _, query := range fs.Args() {
		sel, err := cache.Select(query, arch)
		if err != nil {
			code = imageFail(stderr, cmdName, imageNotFound(query, err))
			continue
		}
		img := sel.Images[0]
		same := slices.DeleteFunc(slices.Clone(all), func(other oci.Image) bool { return other.ID != img.ID })
		outputs = append(outputs, newInspectOutput(img, same))
	}
	if len(outputs) == 0 && code != 0 && strings.TrimSpace(format) != "" && strings.TrimSpace(format) != "json" {
		return code
	}
	usageErr, writeErr := renderInspectFormat(stdout, format, outputs)
	if usageErr != nil {
		return imageUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return imageFail(stderr, cmdName, writeErr)
	}
	return code
}
