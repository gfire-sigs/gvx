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

package gvx

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/oci"
)

// NewLayerCache opens the EROFS layer cache at dir, or the default host cache
// directory when dir is empty. The layers use a block size equal to the Sentry
// page size, because the Sentry refuses an image whose block size is not a
// multiple of its page size. Callers that pull or run images through gvx must
// use this constructor so that both sides agree on the format.
func NewLayerCache(dir string) (*oci.LayerCache, error) {
	return oci.NewLayerCacheWithOptions(dir, oci.CacheOptions{BlockSize: hostarch.PageSize})
}

// elfMachine maps a Linux architecture name to its ELF e_machine value.
func elfMachine(arch string) (elf.Machine, error) {
	switch arch {
	case "amd64":
		return elf.EM_X86_64, nil
	case "arm64":
		return elf.EM_AARCH64, nil
	default:
		return elf.EM_NONE, fmt.Errorf("%w: unsupported guest architecture %q (want amd64 or arm64)", ErrInvalidConfig, arch)
	}
}

// validateELF64Arch verifies that elfData is an ELF64 executable for the
// guest architecture arch.
func validateELF64Arch(elfData []byte, arch string) error {
	want, err := elfMachine(arch)
	if err != nil {
		return err
	}
	ef, err := elf.NewFile(bytes.NewReader(elfData))
	if err != nil {
		return fmt.Errorf("gvx: parse ELF64 binary: %w", err)
	}
	if err := ef.Close(); err != nil {
		return fmt.Errorf("gvx: close parsed ELF64 binary: %w", err)
	}
	if ef.Class != elf.ELFCLASS64 || ef.Machine != want {
		return fmt.Errorf("gvx: ELF architecture mismatch: got (%v, %v), want (ELFCLASS64, %v) for guest architecture %s", ef.Class, ef.Machine, want, arch)
	}
	return nil
}

// elfLayerTar wraps one executable into a single-file OCI layer tar at
// /bin/app.
func elfLayerTar(elfData []byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "bin/app",
		Mode:     0o755,
		Size:     int64(len(elfData)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		return nil, fmt.Errorf("gvx: write ELF layer header: %w", err)
	}
	if _, err := tw.Write(elfData); err != nil {
		return nil, fmt.Errorf("gvx: write ELF layer body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("gvx: close ELF layer tar: %w", err)
	}
	return buf.Bytes(), nil
}

// initOCILayers compiles every layer source into the cache and opens one
// read-only HostHandle per layer, ordered from the lowest layer to the
// highest. The cache verifies each layer file on open. The HostHandle then
// reopens the same path, and the SameFile check rejects a path swapped
// between the two opens.
func (s *Sandbox) initOCILayers(ctx context.Context) (err error) {
	cache, err := NewLayerCache(s.cfg.OCICacheDir)
	if err != nil {
		return err
	}

	var layerFiles []*os.File
	defer func() {
		err = errors.Join(err, oci.CloseLayerFiles(layerFiles))
	}()
	var layerPaths []string

	if len(s.cfg.OCILayerTars) > 0 {
		var digests []string
		for i, rawTar := range s.cfg.OCILayerTars {
			p, stats, err := cache.CompileAndStore("", bytes.NewReader(rawTar))
			if err != nil {
				return fmt.Errorf("gvx: compile OCI layer %d: %w", i, err)
			}
			digests = append(digests, stats.SHA256Hex)
			layerPaths = append(layerPaths, p)
		}
		files, err := cache.OpenLayerHandles(digests)
		if err != nil {
			return err
		}
		layerFiles = append(layerFiles, files...)
	} else if s.cfg.OCIImage != "" {
		img, err := ResolveImage(ctx, cache, s.cfg.RegistryBaseURL, s.cfg.OCIImage, s.cfg.Architecture)
		if err != nil {
			return err
		}
		s.resolvedImg = img
		layerFiles = append(layerFiles, img.LayerFiles...)
		img.LayerFiles = nil
		layerPaths = append(layerPaths, img.LayerPaths...)
		if err := s.applyImageDefaults(img.Config); err != nil {
			return err
		}
	}

	if len(s.cfg.ELFBytes) > 0 || s.cfg.BinaryPath != "" {
		elfData := s.cfg.ELFBytes
		if len(elfData) == 0 {
			var rErr error
			elfData, rErr = os.ReadFile(s.cfg.BinaryPath)
			if rErr != nil {
				return fmt.Errorf("gvx: read binary %q: %w", s.cfg.BinaryPath, rErr)
			}
		}
		if err := validateELF64Arch(elfData, s.cfg.Architecture); err != nil {
			return err
		}
		layerTar, err := elfLayerTar(elfData)
		if err != nil {
			return err
		}
		p, stats, err := cache.CompileAndStore("", bytes.NewReader(layerTar))
		if err != nil {
			return fmt.Errorf("gvx: compile ELF layer: %w", err)
		}
		files, err := cache.OpenLayerHandles([]string{stats.SHA256Hex})
		if err != nil {
			return err
		}
		layerPaths = append(layerPaths, p)
		layerFiles = append(layerFiles, files...)
		if len(s.cfg.Argv) == 0 {
			s.cfg.Argv = []string{"/bin/app"}
		} else if s.cfg.BinaryPath != "" && s.cfg.Argv[0] != "/bin/app" {
			s.cfg.Argv = append([]string{"/bin/app"}, s.cfg.Argv...)
		}
	}

	if len(s.cfg.Argv) == 0 && (len(s.cfg.Cmd) > 0 || s.cfg.EntrypointSet) {
		// A layer tar has no image config: the caller names the whole command.
		if err := s.applyImageDefaults(oci.RuntimeConfig{}); err != nil {
			return err
		}
	}

	if len(layerFiles) != len(layerPaths) {
		return fmt.Errorf("gvx: %d opened EROFS layers but %d layer paths", len(layerFiles), len(layerPaths))
	}
	for i, f := range layerFiles {
		hh, err := fd.OpenHostPath(layerPaths[i], os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("gvx: open EROFS HostHandle %q: %w", layerPaths[i], err)
		}
		s.layerHandles = append(s.layerHandles, hh)
		if err := verifySameLayerFile(f, layerPaths[i]); err != nil {
			return err
		}
	}
	return nil
}

// applyImageDefaults fills the command and the environment of the guest from
// the config of its image. The command follows Docker rules, and the caller
// environment replaces the image values key by key.
func (s *Sandbox) applyImageDefaults(img oci.RuntimeConfig) error {
	argv, err := composeCommand(img, commandSource{
		Argv:          s.cfg.Argv,
		Entrypoint:    s.cfg.Entrypoint,
		EntrypointSet: s.cfg.EntrypointSet,
		Cmd:           s.cfg.Cmd,
	})
	if err != nil {
		return err
	}
	env, err := mergeEnv(img.Env, s.cfg.Envv)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	s.cfg.Argv, s.cfg.Envv = argv, env
	return nil
}

// verifySameLayerFile reports an error when path no longer names the file
// that the cache opened and verified.
func verifySameLayerFile(opened *os.File, path string) error {
	openedInfo, err := opened.Stat()
	if err != nil {
		return fmt.Errorf("gvx: stat opened EROFS layer %q: %w", path, err)
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("gvx: stat EROFS layer path %q: %w", path, err)
	}
	if !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("gvx: EROFS layer %q changed between verification and open", path)
	}
	return nil
}

// ResolveImage resolves image into cached EROFS layers for the Linux
// architecture arch. The image is an OCI archive path or a Docker image
// reference such as "alpine:3.20", "ghcr.io/org/img:v1", or
// "name@sha256:<digest>". The reference names its registry.
//
// A non-empty baseURL, such as the -registry-url flag, overrides the
// registry. The call then drops a registry host in the reference and keeps
// the repository path as written.
//
// A registry pull revalidates the tag over the network. When the registry is
// unreachable, ResolveImage falls back to the image that an earlier pull
// cached. It looks in the cache first. Without an override, it then looks in
// the default host layer cache.
func ResolveImage(ctx context.Context, cache *oci.LayerCache, baseURL, image, arch string) (*oci.ResolvedImage, error) {
	arch = cmp.Or(arch, runtime.GOARCH)
	if info, err := os.Stat(image); err == nil && !info.IsDir() {
		f, err := os.Open(image)
		if err != nil {
			return nil, fmt.Errorf("gvx: open image archive %q: %w", image, err)
		}
		img, loadErr := oci.LoadArchiveTar(f, cache, arch)
		if closeErr := f.Close(); closeErr != nil {
			loadErr = errors.Join(loadErr, fmt.Errorf("gvx: close image archive %q: %w", image, closeErr))
		}
		if loadErr != nil {
			return nil, loadErr
		}
		return img, nil
	}

	explicitRegistry := baseURL != ""
	var ref oci.Reference
	var refErr error
	if explicitRegistry {
		baseURL = strings.TrimRight(baseURL, "/")
		ref, refErr = oci.ParseReferenceAt(image, baseURL)
	} else {
		ref, refErr = oci.ParseReference(image)
		baseURL = ref.BaseURL()
	}
	if refErr != nil {
		return nil, fmt.Errorf("gvx: %q is neither an image archive file nor a valid image reference: %w", image, refErr)
	}
	repo, tag := ref.Repository, ref.ManifestReference()

	img, pullErr := oci.PullRegistryImage(ctx, nil, baseURL, repo, tag, arch, cache)
	if pullErr == nil {
		return img, nil
	}
	if ctx.Err() != nil || !isNetworkError(pullErr) {
		return nil, pullErr
	}

	cached, cacheErr := cache.LoadCachedImage(baseURL, repo, tag, arch)
	if cacheErr == nil {
		return cached, nil
	}
	if !errors.Is(cacheErr, oci.ErrNotCached) {
		return nil, errors.Join(pullErr, cacheErr)
	}
	if !explicitRegistry {
		defaultCache, err := NewLayerCache("")
		if err != nil {
			return nil, errors.Join(pullErr, err)
		}
		if defaultCache.Dir() != cache.Dir() {
			imported, err := cache.ImportCachedImage(defaultCache, baseURL, repo, tag, arch)
			if err == nil {
				return imported, nil
			}
			if !errors.Is(err, oci.ErrNotCached) {
				return nil, errors.Join(pullErr, err)
			}
		}
	}
	return nil, pullErr
}

// isNetworkError reports whether err comes from an unreachable registry, as
// opposed to a registry that answered with a rejection or invalid data.
func isNetworkError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}
