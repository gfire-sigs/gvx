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
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"strings"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// EROFSLayerMount binds one pre-opened EROFS image handle to its guest mount
// target, layer index, and content digest for checkpoint and restore.
type EROFSLayerMount struct {
	MountTarget string
	LayerIndex  int
	Digest      string
	Handle      *fd.HostHandle
}

// normalizeEROFSDigest strips algorithm prefixes and whitespace from digest.
func normalizeEROFSDigest(digest string) string {
	d := strings.ToLower(strings.TrimSpace(digest))
	return strings.TrimPrefix(d, "sha256:")
}

// digestFromLayerPath extracts the cached SHA-256 hex stem from an .erofs path.
func digestFromLayerPath(layerPath string) string {
	base := filepath.Base(layerPath)
	stem := strings.TrimSuffix(base, ".erofs")
	return normalizeEROFSDigest(stem)
}

// EROFSUniqueID derives a deterministic checkpoint.ResourceID for an EROFS
// layer mounted at mountTarget and layerIndex with content digest.
func EROFSUniqueID(mountTarget string, layerIndex int, digest string) checkpoint.ResourceID {
	cleanTarget := path.Clean("/" + strings.TrimSpace(mountTarget))
	normDigest := normalizeEROFSDigest(digest)
	if normDigest != "" {
		return checkpoint.ResourceID{
			Path: fmt.Sprintf("erofs:%s:layer-%d:%s", cleanTarget, layerIndex, normDigest),
		}
	}
	return checkpoint.ResourceID{
		Path: fmt.Sprintf("erofs:%s:layer-%d", cleanTarget, layerIndex),
	}
}

func closeRestoreFDMap(fdMap map[checkpoint.ResourceID]int) error {
	var errs []error
	for _, rawFD := range fdMap {
		if f := os.NewFile(uintptr(rawFD), "erofs-restore-cleanup"); f != nil {
			errs = append(errs, f.Close())
		}
	}
	return errors.Join(errs...)
}

// BuildRestoreEROFSFDMap duplicates each pre-opened EROFS HostHandle in layers
// into a vfs.CtxRestoreFilesystemFDMap keyed by deterministic EROFSUniqueID.
// The restored EROFS filesystems take ownership of the duplicated descriptors
// during state.Load.
func BuildRestoreEROFSFDMap(layers []EROFSLayerMount) (map[checkpoint.ResourceID]int, error) {
	fdMap := make(map[checkpoint.ResourceID]int, len(layers))
	for i, layer := range layers {
		if layer.Handle == nil {
			return nil, errors.Join(fmt.Errorf("gvx: nil EROFS HostHandle at entry %d", i), closeRestoreFDMap(fdMap))
		}
		id := EROFSUniqueID(layer.MountTarget, layer.LayerIndex, layer.Digest)
		if _, exists := fdMap[id]; exists {
			return nil, errors.Join(fmt.Errorf("gvx: duplicate EROFS restore UniqueID %q", id), closeRestoreFDMap(fdMap))
		}
		dupHH, err := layer.Handle.Dup()
		if err != nil {
			return nil, errors.Join(fmt.Errorf("gvx: dup EROFS layer handle %q: %w", id, err), closeRestoreFDMap(fdMap))
		}
		dupFD, err := dupHH.Release()
		if err != nil {
			_ = dupHH.Close()
			return nil, errors.Join(fmt.Errorf("gvx: release dup EROFS layer handle %q: %w", id, err), closeRestoreFDMap(fdMap))
		}
		fdMap[id] = int(dupFD)
	}
	return fdMap, nil
}

// WithRestoreEROFSFDMap populates vfs.CtxRestoreFilesystemFDMap on ctx from
// pre-opened EROFS layer handles. When ctx implements pkg/context.Context, the
// returned context preserves that interface.
func WithRestoreEROFSFDMap(ctx context.Context, layers []EROFSLayerMount) (context.Context, error) {
	fdMap, err := BuildRestoreEROFSFDMap(layers)
	if err != nil {
		return nil, err
	}
	if existing := vfs.RestoreFilesystemFDMapFromContext(ctx); len(existing) > 0 {
		for id := range fdMap {
			if _, exists := existing[id]; exists {
				return nil, errors.Join(fmt.Errorf("gvx: duplicate EROFS restore UniqueID %q in context", id), closeRestoreFDMap(fdMap))
			}
		}
		merged := make(map[checkpoint.ResourceID]int, len(existing)+len(fdMap))
		maps.Copy(merged, existing)
		maps.Copy(merged, fdMap)
		fdMap = merged
	}
	if gctx, ok := ctx.(gvcontext.Context); ok {
		return gvcontext.WithValue(gctx, vfs.CtxRestoreFilesystemFDMap, fdMap), nil
	}
	return context.WithValue(ctx, vfs.CtxRestoreFilesystemFDMap, fdMap), nil
}

// EROFSLayerMounts returns the pre-opened rootfs EROFS layer descriptors and
// deterministic restore metadata for s.
func (s *Sandbox) EROFSLayerMounts() []EROFSLayerMount {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]EROFSLayerMount, len(s.layerHandles))
	for i, hh := range s.layerHandles {
		var digest string
		if i < len(s.layerDigests) {
			digest = s.layerDigests[i]
		}
		out[i] = EROFSLayerMount{
			MountTarget: "/",
			LayerIndex:  i,
			Digest:      digest,
			Handle:      hh,
		}
	}
	return out
}

// WithRestoreEROFSFDMap populates vfs.CtxRestoreFilesystemFDMap on ctx from
// the pre-opened rootfs EROFS layer handles of s.
func (s *Sandbox) WithRestoreEROFSFDMap(ctx context.Context) (context.Context, error) {
	return WithRestoreEROFSFDMap(ctx, s.EROFSLayerMounts())
}
