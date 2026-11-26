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

package hostfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strings"
)

// This file holds the rules for symbolic links in a workspace and the embedder
// query API for virtual symbolic links.
//
// Two kinds of symbolic link exist in a workspace:
//
//   - A virtual symbolic link lives only in .gvx_meta under a kindName or
//     kindPathName key. The host never receives a link, so the host kernel
//     never follows one. The Sentry VFS resolves the target string in the guest
//     mount namespace.
//   - A native host symbolic link lives on the host filesystem. In default
//     SymlinkVirtual mode, only host processes create them. In opt-in
//     SymlinkContained mode on Unix hosts, hostfs materializes guest-created
//     symbolic links via symlinkat(2) when all containment invariants hold;
//     non-eligible targets and Windows hosts stay virtual in .gvx_meta.

// SymlinkMode selects how hostfs stores guest-created symbolic links.
type SymlinkMode string

const (
	// SymlinkVirtual stores every guest-created symbolic link only in
	// .gvx_meta. It is the default when SymlinkMode is empty.
	SymlinkVirtual SymlinkMode = "virtual"

	// SymlinkContained materializes contained relative guest symbolic links on
	// Unix hosts via symlinkat(2). Non-eligible targets and Windows hosts fall
	// back to virtual entries in .gvx_meta.
	SymlinkContained SymlinkMode = "contained"
)

// VirtualSymlink describes one guest-created symbolic link stored only in
// .gvx_meta.
type VirtualSymlink struct {
	Path   string
	Target string
}

const (
	// maxSymlinkHops bounds host symlink expansion during target validation,
	// matching Linux MAXSYMLINKS.
	maxSymlinkHops = 40

	// maxTargetWalkComponents bounds total path components visited while
	// validating a target chain against pre-existing host symlinks.
	maxTargetWalkComponents = 4096

	// darwinMaxSymlinkTargetLen is macOS MAXPATHLEN - 1. Targets longer than
	// this length fall back to virtual so Linux 4095-byte targets keep working.
	darwinMaxSymlinkTargetLen = 1023
)

var (
	// errSymlinkEmpty reports an empty target. It wraps fs.ErrNotExist, so the
	// guest sees ENOENT as on Linux.
	errSymlinkEmpty = fmt.Errorf("hostfs: empty symbolic link target: %w", fs.ErrNotExist)

	// errSymlinkNUL reports a target that holds a NUL byte. It wraps
	// fs.ErrInvalid, so the guest sees EINVAL.
	errSymlinkNUL = fmt.Errorf("hostfs: symbolic link target holds a NUL byte: %w", fs.ErrInvalid)

	// errFallbackVirtual is an internal sentinel indicating that host symlink
	// creation should fall back to a virtual record in .gvx_meta.
	errFallbackVirtual = errors.New("hostfs: fall back to virtual symbolic link")
)

// parseSymlinkMode validates and normalizes mode. An empty mode selects
// SymlinkVirtual.
func parseSymlinkMode(mode SymlinkMode) (SymlinkMode, error) {
	switch mode {
	case "", SymlinkVirtual:
		return SymlinkVirtual, nil
	case SymlinkContained:
		return SymlinkContained, nil
	default:
		return "", fmt.Errorf("hostfs: unsupported SymlinkMode %q (want %q or %q)", mode, SymlinkVirtual, SymlinkContained)
	}
}

// validateGuestSymlinkTarget checks the target of a guest symbolic link. It
// rejects the empty target and a target with a NUL byte. Every other string is
// valid in guest VFS semantics.
func validateGuestSymlinkTarget(target string) error {
	switch {
	case target == "":
		return errSymlinkEmpty
	case strings.IndexByte(target, 0) >= 0:
		return errSymlinkNUL
	}
	return nil
}

// relDepth returns the directory depth of a cleaned workspace-relative
// directory path: "." has depth 0, "a" has depth 1, "a/b" has depth 2.
func relDepth(dirRel string) int {
	if dirRel == "" || dirRel == "." {
		return 0
	}
	return strings.Count(dirRel, "/") + 1
}

// containedTarget is the parsed form of a symlink target that satisfies the
// prefix-only non-depth-reducing containment rule.
type containedTarget struct {
	// leadingParents is the count of leading ".." components (k >= 0).
	leadingParents int
	// baseDir is the cleaned workspace-relative directory reached after
	// climbing leadingParents levels from the link's parent directory.
	baseDir string
	// comps holds the ordinary non-empty, non-".", non-".." components
	// following the leading ".." prefix. Always satisfies len(comps) > leadingParents.
	comps []string
	// resolved is the cleaned workspace-relative path obtained by joining
	// baseDir and comps. It is never "." and never escapes the workspace.
	resolved string
}

// classifyContainedTarget checks whether target at cleaned workspace-relative
// path linkRel satisfies the structural containment invariants:
//
//  1. Non-empty, no NUL, strictly relative (no leading '/'), no '\\' or ':'.
//  2. Every ".." segment appears before any ordinary component (prefix-only "..").
//  3. Ordinary components strictly outnumber leading ".." segments
//     (len(comps) > leadingParents). This rejects ".", bare "..", and
//     depth-reducing links so no composition or substitution can decrease
//     effective depth below a real directory at linkRel.
//  4. Leading ".." count does not exceed the parent directory depth of linkRel.
func classifyContainedTarget(linkRel, target string) (containedTarget, bool) {
	if validateGuestSymlinkTarget(target) != nil {
		return containedTarget{}, false
	}
	if strings.HasPrefix(target, "/") || strings.ContainsAny(target, `\:`) {
		return containedTarget{}, false
	}
	var (
		seenName       bool
		leadingParents int
		comps          []string
	)
	for _, seg := range strings.Split(target, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if seenName {
				return containedTarget{}, false
			}
			leadingParents++
		default:
			seenName = true
			comps = append(comps, seg)
		}
	}
	if len(comps) == 0 || len(comps) <= leadingParents {
		return containedTarget{}, false
	}
	parentRel, _ := splitParent(linkRel)
	parentDepth := relDepth(parentRel)
	if leadingParents > parentDepth {
		return containedTarget{}, false
	}
	baseDir := climbRel(parentRel, leadingParents)
	resolved := baseDir
	for _, c := range comps {
		resolved = joinRelPath(resolved, c)
	}
	if resolved == "" || resolved == "." {
		return containedTarget{}, false
	}
	return containedTarget{
		leadingParents: leadingParents,
		baseDir:        baseDir,
		comps:          comps,
		resolved:       resolved,
	}, true
}

// climbRel removes k trailing components from cleaned directory path dirRel.
// Precondition: 0 <= k <= relDepth(dirRel).
func climbRel(dirRel string, k int) string {
	if k == 0 || dirRel == "." {
		return dirRel
	}
	parts := strings.Split(dirRel, "/")
	if k >= len(parts) {
		return "."
	}
	return strings.Join(parts[:len(parts)-k], "/")
}

// isReservedRootNameFold reports whether name matches a hidden workspace root
// metadata filename case-insensitively.
func isReservedRootNameFold(name string) bool {
	lower := strings.ToLower(name)
	return lower == MetaFileName || lower == MetaLockFileName || lower == metaTempName || strings.HasPrefix(lower, metaTempPrefix)
}

// isInternalNameFold reports whether name starts with an internal hostfs
// ephemeral or NameCodec escape prefix case-insensitively.
func isInternalNameFold(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, codecPrefix) || strings.HasPrefix(lower, unlinkedTmpPrefix)
}

// targetsHiddenPathLocked reports whether resolved (a cleaned non-root
// workspace-relative path) names or traverses a reserved metadata file or an
// internal ephemeral/escaped filename.
func (w *Workspace) targetsHiddenPathLocked(resolved string) bool {
	if resolved == "" || resolved == "." {
		return true
	}
	for i, comp := range strings.Split(resolved, "/") {
		if i == 0 && !w.externalMeta && isReservedRootNameFold(comp) {
			return true
		}
		if isInternalNameFold(comp) {
			return true
		}
	}
	return false
}

// remapPath translates logical post-operation path rel to its current on-disk
// path using overrides. An empty string result means the path will not exist
// on disk after the operation.
func remapPath(rel string, overrides map[string]string) (string, bool) {
	if len(overrides) == 0 || rel == "." {
		return rel, true
	}
	for dst, src := range overrides {
		if rel == dst {
			if src == "" {
				return "", false
			}
			return src, true
		}
		if strings.HasPrefix(rel, dst+"/") {
			if src == "" {
				return "", false
			}
			return src + strings.TrimPrefix(rel, dst), true
		}
	}
	return rel, true
}

// validPlainComponentLocked reports whether comp is a plain, unencoded host
// filename that does not collide with internal prefixes or Unicode
// normalization rules.
func (w *Workspace) validPlainComponentLocked(curLogicalDir, comp string) bool {
	if comp == "" || comp == "." || comp == ".." {
		return false
	}
	if curLogicalDir == "." && !w.externalMeta && isReservedRootNameFold(comp) {
		return false
	}
	if isInternalNameFold(comp) {
		return false
	}
	if w.caps.UnicodeNormalized && !isASCII(comp) {
		return false
	}
	form0, err := w.codec.leafForm(comp)
	return err == nil && form0 == comp
}

// verifyHostTargetChainLocked walks ct from ct.baseDir through existing host
// entries using non-following pinned calls. It rejects any target that:
//   - uses a component requiring NameCodec escaping or Unicode normalization,
//   - collides with a different-case or hidden host entry,
//   - targets reserved metadata or internal filenames, or
//   - traverses any pre-existing host symlink that does not itself satisfy
//     classifyContainedTarget (or exceeds maxSymlinkHops / maxTargetWalkComponents).
//
// Callers hold w.mu.
func (w *Workspace) verifyHostTargetChainLocked(ct containedTarget, overrides map[string]string, badDstLeaf map[string]struct{}) bool {
	if w.targetsHiddenPathLocked(ct.resolved) {
		return false
	}
	curDir := ct.baseDir
	comps := ct.comps
	idx := 0
	hops := 0
	visited := 0
	existsOnHost := true

	for idx < len(comps) {
		visited++
		if visited > maxTargetWalkComponents {
			return false
		}
		comp := comps[idx]
		if !w.validPlainComponentLocked(curDir, comp) {
			return false
		}
		nextLogical := joinRelPath(curDir, comp)
		if _, bad := badDstLeaf[nextLogical]; bad {
			return false
		}
		if !existsOnHost {
			curDir = nextLogical
			idx++
			continue
		}

		physNext, ok := remapPath(nextLogical, overrides)
		if !ok {
			existsOnHost = false
			curDir = nextLogical
			idx++
			continue
		}
		physDir, physComp := splitParent(physNext)
		if w.stateful {
			if alt, hasAlt := w.altLeaf(physDir, physComp); hasAlt && alt != physComp {
				return false
			}
		}

		pin, err := w.acquireFreshPin(physDir)
		if err != nil {
			if isNotExist(err) || errors.Is(err, errNotDir) {
				existsOnHost = false
				curDir = nextLogical
				idx++
				continue
			}
			return false
		}
		probe, perr := w.locateIn(physDir, physComp, pin, func(leaf string) (hostInfo, error) {
			return w.host.lstatAt(pin.h, leaf)
		})
		if perr != nil {
			w.releasePin(pin)
			if isNotExist(perr) {
				existsOnHost = false
				curDir = nextLogical
				idx++
				continue
			}
			return false
		}
		if !probe.found {
			w.releasePin(pin)
			if probe.collided || !isNotExist(probe.err) {
				return false
			}
			existsOnHost = false
			curDir = nextLogical
			idx++
			continue
		}
		if probe.hidden || probe.leaf != physComp {
			w.releasePin(pin)
			return false
		}
		switch probe.info.kind {
		case hostKindDir:
			w.releasePin(pin)
			curDir = nextLogical
			idx++
		case hostKindSymlink:
			subTarget, rerr := w.host.readlinkAt(pin.h, probe.leaf)
			w.releasePin(pin)
			if rerr != nil {
				return false
			}
			subCT, ok := classifyContainedTarget(nextLogical, subTarget)
			if !ok || w.targetsHiddenPathLocked(subCT.resolved) {
				return false
			}
			hops++
			if hops > maxSymlinkHops {
				return false
			}
			rest := comps[idx+1:]
			if len(subCT.comps)+len(rest) > maxTargetWalkComponents {
				return false
			}
			nextComps := make([]string, 0, len(subCT.comps)+len(rest))
			nextComps = append(nextComps, subCT.comps...)
			nextComps = append(nextComps, rest...)
			curDir = subCT.baseDir
			comps = nextComps
			idx = 0
			existsOnHost = true
		default:
			w.releasePin(pin)
			existsOnHost = false
			curDir = nextLogical
			idx++
		}
	}
	return true
}

// hostSymlinkSafeAtLocked reports whether a host symbolic link at destRel with
// stored host name destLeaf and target string target satisfies all containment
// invariants. Callers hold w.mu.
func (w *Workspace) hostSymlinkSafeAtLocked(destRel, destLeaf, target string, overrides map[string]string, badDstLeaf map[string]struct{}) (containedTarget, bool) {
	parentRel, destName := splitParent(destRel)
	if destLeaf != destName || !w.validPlainComponentLocked(parentRel, destName) {
		return containedTarget{}, false
	}
	ct, ok := classifyContainedTarget(destRel, target)
	if !ok {
		return containedTarget{}, false
	}
	if !w.verifyHostTargetChainLocked(ct, overrides, badDstLeaf) {
		return containedTarget{}, false
	}
	return ct, true
}

// canMaterializeSymlinkLocked reports whether a newly created guest symlink at
// rel with host leaf and target may be materialized as a real host symlink.
// Callers hold w.mu.
func (w *Workspace) canMaterializeSymlinkLocked(rel, leaf, target string) (containedTarget, bool) {
	if w.symlinkMode != SymlinkContained || runtime.GOOS == "windows" {
		return containedTarget{}, false
	}
	if runtime.GOOS == "darwin" && len(target) > darwinMaxSymlinkTargetLen {
		return containedTarget{}, false
	}
	return w.hostSymlinkSafeAtLocked(rel, leaf, target, nil, nil)
}

// VirtualSymlinks returns the sorted guest-created symbolic links currently
// stored only in .gvx_meta for this workspace.
func (w *Workspace) VirtualSymlinks() ([]VirtualSymlink, error) {
	w.maybeRefreshMeta(true)
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, os.ErrClosed
	}
	if !w.meta.hasNames() {
		return nil, nil
	}
	var out []VirtualSymlink
	stack := []string{"."}
	for len(stack) > 0 {
		dirRel := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		pin, err := w.acquirePin(dirRel)
		if err != nil {
			if isNotExist(err) || errors.Is(err, fs.ErrPermission) {
				continue
			}
			return nil, err
		}
		dirKey := w.dirKeyOf(pin, dirRel)
		for _, name := range w.meta.kidsOf(dirKey) {
			if r := w.meta.get(dirKey.withName(name)); r != nil && r.attr.Symlink != "" {
				out = append(out, VirtualSymlink{
					Path:   joinRelPath(dirRel, name),
					Target: r.attr.Symlink,
				})
			}
		}
		entries, rerr := w.host.readDirAt(pin.h)
		w.releasePin(pin)
		if rerr != nil {
			if isNotExist(rerr) || errors.Is(rerr, fs.ErrPermission) {
				continue
			}
			return nil, rerr
		}
		for _, e := range entries {
			if e.kind != hostKindDir {
				continue
			}
			if (dirRel == "." && w.isReservedPath(e.name)) || w.hiddenByName(e.name) {
				continue
			}
			guest := w.listName(dirRel, e.name)
			stack = append(stack, joinRelPath(dirRel, guest))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// VirtualSymlinksAt reads the .gvx_meta file at metaPath, resolves
// identity-keyed records against workspaceDir, and returns the sorted list of
// guest-created virtual symbolic links. If workspaceDir exists as a directory
// and metaPath does not exist, VirtualSymlinksAt returns nil, nil.
func VirtualSymlinksAt(metaPath, workspaceDir string) ([]VirtualSymlink, error) {
	info, err := os.Stat(workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("hostfs: stat workspace %q: %w", workspaceDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("hostfs: workspace %q must be a directory", workspaceDir)
	}
	recs, err := ReadMetaAt(metaPath, workspaceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []VirtualSymlink
	for rel, attr := range recs {
		if attr.Symlink != "" {
			out = append(out, VirtualSymlink{Path: rel, Target: attr.Symlink})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
