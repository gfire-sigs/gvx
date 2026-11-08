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
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/oci"
)

// imageCacheFlags are the flags that every image command shares.
type imageCacheFlags struct {
	cacheDir *string
	arch     *string
	tune     *tuneFlags
}

func addImageCacheFlags(fs *flag.FlagSet) imageCacheFlags {
	return imageCacheFlags{
		cacheDir: fs.String("cache-dir", "", "EROFS layer cache directory"),
		arch:     fs.String("arch", runtime.GOARCH, "Target Linux architecture (amd64 or arm64)"),
		tune:     addTuneFlags(fs),
	}
}

// hostDNSUsage is the help text of --host-dns on every command that contacts a
// registry.
const hostDNSUsage = "DNS server of the host as IP or IP:PORT, repeatable; it replaces the discovery of the host resolver (for an Android app)"

// addHostDNSFlag registers the repeatable --host-dns flag.
func addHostDNSFlag(fs *flag.FlagSet) *multiStringFlag {
	var servers multiStringFlag
	fs.Var(&servers, "host-dns", hostDNSUsage)
	return &servers
}

// openPullCache opens the layer cache that the flags name for a command that
// pulls. The registry requests of the cache resolve names through hostDNS
// when it is not empty.
func (f imageCacheFlags) openPullCache(hostDNS []string) (*oci.LayerCache, string, error) {
	servers, err := gvx.ParseHostDNSServers(hostDNS)
	if err != nil {
		return nil, "", fmt.Errorf("--host-dns: %w", err)
	}
	cache, arch, err := f.open()
	if err != nil {
		return nil, "", err
	}
	cache.SetDNSServers(servers)
	return cache, arch, nil
}

// open opens the layer cache that the flags name and returns it with the
// architecture.
func (f imageCacheFlags) open() (*oci.LayerCache, string, error) {
	tuned, err := f.tune.values()
	if err != nil {
		return nil, "", err
	}
	cache, err := gvx.NewLayerCacheWithTuning(strings.TrimSpace(*f.cacheDir), tuned)
	if err != nil {
		return nil, "", err
	}
	return cache, strings.TrimSpace(*f.arch), nil
}

// newImageFlagSet creates the flag set of an image command. The flag package
// prints its errors to stderr.
func newImageFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("rungv "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseImageFlags parses args. stop is true when the command must return code.
func parseImageFlags(fs *flag.FlagSet, args []string) (code int, stop bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return 2, true
	}
	return 0, false
}

// imageFail prints a command error and returns the exit code 1.
func imageFail(stderr io.Writer, command string, err error) int {
	_, _ = fmt.Fprintf(stderr, "rungv %s: %v\n", command, err)
	return 1
}

// imageUsageError prints a usage error and returns the exit code 2.
func imageUsageError(stderr io.Writer, command, format string, args ...any) int {
	_, _ = fmt.Fprintf(stderr, "rungv %s: %s\n", command, fmt.Sprintf(format, args...))
	return 2
}

// shortImageID returns the 12 hex digits that Docker shows for an image ID.
func shortImageID(id string) string {
	hexID := strings.TrimPrefix(id, "sha256:")
	if len(hexID) > 12 {
		return hexID[:12]
	}
	return hexID
}
