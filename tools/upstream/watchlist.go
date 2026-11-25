package main

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
)

// semanticWatchlistPrefixes lists upstream subtrees whose semantic or security
// contract changes can silently affect custom gvx VFS drivers (hostfs,
// ext4lite, rpcfs, and erofs xattr hooks) without causing compile errors.
var semanticWatchlistPrefixes = []string{
	"pkg/sentry/vfs/",
	"pkg/sentry/kernel/auth/",
	"pkg/sentry/fsimpl/tmpfs/",
	"pkg/sentry/fsimpl/memxattr/",
}

// isWatchlistPath reports whether slash-normalized relPath falls under any
// semantic parity watchlist prefix.
func isWatchlistPath(relPath string) bool {
	clean := strings.TrimPrefix(filepath.ToSlash(relPath), "./")
	for _, prefix := range semanticWatchlistPrefixes {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

// FilterWatchlistPaths returns the sorted, deduplicated subset of paths that
// belong to the semantic parity watchlist.
func FilterWatchlistPaths(paths []string) []string {
	var hits []string
	for _, p := range paths {
		clean := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(p)), "./")
		if clean != "" && isWatchlistPath(clean) {
			hits = append(hits, clean)
		}
	}
	slices.Sort(hits)
	return slices.Compact(hits)
}

// CollectWatchlistChanges returns the sorted list of watchlist files added,
// deleted, or modified between oldTree and newTree.
func CollectWatchlistChanges(oldTree, newTree *UpstreamTree) []string {
	if oldTree == nil || newTree == nil {
		return nil
	}
	var changed []string
	for rel, newBytes := range newTree.Files {
		if !isWatchlistPath(rel) {
			continue
		}
		if oldBytes, ok := oldTree.Files[rel]; !ok || !bytes.Equal(oldBytes, newBytes) {
			changed = append(changed, rel)
		}
	}
	for rel := range oldTree.Files {
		if !isWatchlistPath(rel) {
			continue
		}
		if _, ok := newTree.Files[rel]; !ok {
			changed = append(changed, rel)
		}
	}
	return FilterWatchlistPaths(changed)
}

func printWatchlistNotice(w io.Writer, hits []string) {
	if len(hits) == 0 {
		return
	}
	fmt.Fprintf(w, "semantic parity watchlist: %d upstream file(s) changed in VFS/auth/tmpfs/memxattr (audit hostfs, ext4lite, rpcfs, erofs):\n", len(hits))
	for _, p := range hits {
		fmt.Fprintf(w, "  watchlist: %s\n", p)
	}
}
