package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

const (
	// DefaultUpstreamRepoURL is the canonical upstream gVisor Git repository.
	DefaultUpstreamRepoURL = "https://github.com/google/gvisor.git"

	// DefaultCodeloadBaseURL is the GitHub archive base URL for downloading snapshots.
	DefaultCodeloadBaseURL = "https://codeload.github.com/google/gvisor/tar.gz"

	upstreamModulePath = "gvisor.dev/gvisor"
	targetModulePath   = "z.gfire.dev/gvx"
	// upstreamXSysUnix is the import of the x/sys unix package in upstream code.
	// The module keeps its own copy of that package, because it adds Linux types
	// and constants for Windows and reshapes some Darwin types. A replace directive
	// would not reach a module that imports pkg/gvx, so the import path changes.
	upstreamXSysUnix     = `"golang.org/x/sys/unix"`
	targetXSysUnix       = `"z.gfire.dev/gvx/third_party/x_sys/unix"`
	maxExtractedFileSize = 64 * 1024 * 1024
)

var (
	errInvalidMaskRule     = errors.New("invalid file mask directive line")
	errUnsafeArchivePath   = errors.New("unsafe relative path in upstream archive")
	errUpstreamRefNotFound = errors.New("upstream git reference not found")
	errHTTPStatus          = errors.New("unexpected HTTP status downloading upstream archive")
)

// MaskDecision represents the disposition of a relative repository path under FileMask.
type MaskDecision int

const (
	MaskExclude MaskDecision = iota
	MaskProtect
	MaskInclude
)

// FileMask evaluates repository paths against PROTECT, EXCLUDE, and INCLUDE rules.
type FileMask struct {
	protectRules []string
	excludeRules []string
	includeRules []string
}

// LoadFileMask parses a file_mask.txt specification from maskPath.
func LoadFileMask(maskPath string) (_ *FileMask, err error) {
	f, err := os.Open(maskPath)
	if err != nil {
		return nil, fmt.Errorf("open file mask %s: %w", maskPath, err)
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()

	return ParseFileMaskReader(f)
}

// ParseFileMaskReader parses PROTECT, EXCLUDE, and INCLUDE rules from r.
func ParseFileMaskReader(r io.Reader) (*FileMask, error) {
	mask := &FileMask{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%w: %q", errInvalidMaskRule, line)
		}
		directive := fields[0]
		pattern := filepath.ToSlash(fields[1])
		switch directive {
		case "PROTECT":
			mask.protectRules = append(mask.protectRules, pattern)
		case "EXCLUDE":
			mask.excludeRules = append(mask.excludeRules, pattern)
		case "INCLUDE":
			mask.includeRules = append(mask.includeRules, pattern)
		default:
			return nil, fmt.Errorf("%w: unknown directive %q", errInvalidMaskRule, directive)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan file mask: %w", err)
	}
	return mask, nil
}

// Decide evaluates relPath and returns MaskProtect, MaskExclude, or MaskInclude.
// Precedence order is strictly PROTECT > EXCLUDE > INCLUDE; unmatched paths default to MaskExclude.
func (m *FileMask) Decide(relPath string) MaskDecision {
	clean := strings.TrimPrefix(filepath.ToSlash(relPath), "./")
	if clean == "" || clean == "." {
		return MaskExclude
	}
	for _, pat := range m.protectRules {
		if matchMaskPattern(pat, clean) {
			return MaskProtect
		}
	}
	for _, pat := range m.excludeRules {
		if matchMaskPattern(pat, clean) {
			return MaskExclude
		}
	}
	for _, pat := range m.includeRules {
		if matchMaskPattern(pat, clean) {
			return MaskInclude
		}
	}
	return MaskExclude
}

func matchMaskPattern(pattern, relPath string) bool {
	if pattern == relPath {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return relPath == prefix || strings.HasPrefix(relPath, prefix+"/")
	}
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		return path.Base(relPath) == suffix || strings.HasSuffix(relPath, "/"+suffix)
	}
	if !strings.Contains(pattern, "/") {
		matched, err := path.Match(pattern, path.Base(relPath))
		return err == nil && matched
	}
	matched, err := path.Match(pattern, relPath)
	return err == nil && matched
}

// UpstreamRefInfo holds the resolved commit SHAs for the upstream go branch and latest release tag.
type UpstreamRefInfo struct {
	GoBranchSHA   string `json:"go_branch_sha"`
	ReleaseTag    string `json:"release_tag"`
	ReleaseTagSHA string `json:"release_tag_sha"`
}

// ResolveUpstreamRefs queries repoURL via git ls-remote to resolve refs/heads/go and the latest release-* tag.
func ResolveUpstreamRefs(ctx context.Context, repoURL string) (UpstreamRefInfo, error) {
	repoURL = cmp.Or(repoURL, DefaultUpstreamRepoURL)
	cmd := exec.CommandContext(ctx, "git", "ls-remote", repoURL, "refs/heads/go", "refs/tags/release-*")
	out, err := cmd.Output()
	if err != nil {
		return UpstreamRefInfo{}, fmt.Errorf("git ls-remote %s: %w", repoURL, err)
	}
	return parseLsRemoteOutput(string(out))
}

func parseLsRemoteOutput(raw string) (UpstreamRefInfo, error) {
	var info UpstreamRefInfo
	type tagEntry struct {
		name string
		sha  string
	}
	var tags []tagEntry

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sha, ref := fields[0], fields[1]
		if ref == "refs/heads/go" {
			info.GoBranchSHA = sha
			continue
		}
		if strings.HasPrefix(ref, "refs/tags/release-") {
			tagName := strings.TrimPrefix(ref, "refs/tags/")
			tagName = strings.TrimSuffix(tagName, "^{}")
			tags = append(tags, tagEntry{name: tagName, sha: sha})
		}
	}

	if len(tags) > 0 {
		slices.SortFunc(tags, func(a, b tagEntry) int {
			return strings.Compare(a.name, b.name)
		})
		latest := tags[len(tags)-1]
		info.ReleaseTag = latest.name
		info.ReleaseTagSHA = latest.sha
	}

	if info.GoBranchSHA == "" && info.ReleaseTagSHA == "" {
		return UpstreamRefInfo{}, errUpstreamRefNotFound
	}
	info.GoBranchSHA = cmp.Or(info.GoBranchSHA, info.ReleaseTagSHA)
	return info, nil
}

// SyncConfig configures an upstream snapshot download and masked extraction.
type SyncConfig struct {
	RootDir    string
	DestSubdir string
	RepoURL    string
	TargetRef  string
	Mask       *FileMask
	// Patches, when set, runs RetagFiles on the destination after extraction.
	Patches *PatchSet
	Source  ArchiveSource
}

// SyncManifest records the result of an upstream sync.
type SyncManifest struct {
	GoBranchSHA    string `json:"go_branch_sha"`
	ReleaseTag     string `json:"release_tag"`
	ReleaseTagSHA  string `json:"release_tag_sha"`
	ExtractedFiles int    `json:"extracted_files"`
	ProtectedSkips int    `json:"protected_skips"`
	ExcludedSkips  int    `json:"excluded_skips"`
	DestDir        string `json:"dest_dir"`
	Strategy       string `json:"strategy,omitempty"`
}

// Sync strategy names recorded in the manifest.
const (
	StrategyArchive = "archive"
	StrategyGit     = "git"
)

// SyncUpstream resolves the upstream commit, loads its archive, and extracts masked files into DestSubdir.
//
// This is the archive-overlay fallback for repositories that share no git history with upstream.
func SyncUpstream(ctx context.Context, cfg SyncConfig) (SyncManifest, error) {
	cfg.RootDir = cmp.Or(cfg.RootDir, ".")
	cfg.DestSubdir = cmp.Or(cfg.DestSubdir, ".")

	var refs UpstreamRefInfo
	if cfg.TargetRef != "" {
		sha, err := ValidateCommitSHA(cfg.TargetRef)
		if err != nil {
			return SyncManifest{}, err
		}
		refs = UpstreamRefInfo{GoBranchSHA: sha, ReleaseTag: "pinned", ReleaseTagSHA: sha}
	} else {
		var err error
		refs, err = ResolveUpstreamRefs(ctx, cfg.RepoURL)
		if err != nil {
			return SyncManifest{}, err
		}
	}

	tree, err := cfg.Source.Load(ctx, refs.GoBranchSHA)
	if err != nil {
		return SyncManifest{}, err
	}

	destRoot := filepath.Clean(filepath.Join(cfg.RootDir, cfg.DestSubdir))
	if err := os.MkdirAll(destRoot, 0o755); err != nil {
		return SyncManifest{}, fmt.Errorf("mkdir %s: %w", destRoot, err)
	}
	manifest, err := ExtractMasked(tree, destRoot, cfg.Mask)
	if err != nil {
		return SyncManifest{}, err
	}
	manifest.GoBranchSHA = refs.GoBranchSHA
	manifest.ReleaseTag = refs.ReleaseTag
	manifest.ReleaseTagSHA = refs.ReleaseTagSHA
	manifest.DestDir = destRoot
	manifest.Strategy = StrategyArchive

	if cfg.Patches != nil {
		if _, err := RetagFiles(destRoot, cfg.Patches); err != nil {
			return manifest, fmt.Errorf("retag after extraction: %w", err)
		}
	}
	if err := WriteSyncRecord(cfg.RootDir, manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

// WriteSyncRecord writes UPSTREAM_COMMIT and tools/upstream/sync_manifest.json.
func WriteSyncRecord(rootDir string, manifest SyncManifest) error {
	commitFile := filepath.Join(rootDir, "UPSTREAM_COMMIT")
	if err := os.WriteFile(commitFile, []byte(manifest.GoBranchSHA+"\n"), 0o644); err != nil {
		return fmt.Errorf("write UPSTREAM_COMMIT: %w", err)
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sync manifest: %w", err)
	}
	manifestPath := filepath.Join(rootDir, "tools", "upstream", "sync_manifest.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for sync manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, append(manifestBytes, '\n'), 0o644); err != nil {
		return fmt.Errorf("write sync manifest: %w", err)
	}
	return nil
}

// ExtractMasked writes the files of tree that mask INCLUDEs into destRoot.
//
// Go and assembly files get the gvx module path. go.mod and go.sum merge with the existing
// files so that gvx-only requirements and replace directives survive.
func ExtractMasked(tree *UpstreamTree, destRoot string, mask *FileMask) (SyncManifest, error) {
	var manifest SyncManifest
	paths := make([]string, 0, len(tree.Files))
	for rel := range tree.Files {
		paths = append(paths, rel)
	}
	slices.Sort(paths)

	for _, rel := range paths {
		decision := MaskInclude
		if mask != nil {
			decision = mask.Decide(rel)
		}
		switch decision {
		case MaskProtect:
			manifest.ProtectedSkips++
			continue
		case MaskExclude:
			manifest.ExcludedSkips++
			continue
		case MaskInclude:
		}
		if err := extractSingleFile(tree.Files[rel], destRoot, rel); err != nil {
			return SyncManifest{}, err
		}
		manifest.ExtractedFiles++
	}
	return manifest, nil
}

func stripArchiveRootPrefix(entryName string) (string, error) {
	normalized := filepath.ToSlash(entryName)
	_, after, ok := strings.Cut(normalized, "/")
	if !ok || after == "" {
		return "", nil
	}
	cleaned := path.Clean(after)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("%w: %q", errUnsafeArchivePath, entryName)
	}
	return cleaned, nil
}

func extractSingleFile(data []byte, destRoot, relSlash string) error {
	targetPath := filepath.Join(destRoot, filepath.FromSlash(relSlash))
	relCheck, err := filepath.Rel(destRoot, targetPath)
	if err != nil || strings.HasPrefix(filepath.ToSlash(relCheck), "../") {
		return fmt.Errorf("%w: %s escapes %s", errUnsafeArchivePath, relSlash, destRoot)
	}

	switch {
	case relSlash == "go.mod":
		existing, err := os.ReadFile(targetPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read existing go.mod: %w", err)
		}
		data, err = MergeGoMod(data, existing)
		if err != nil {
			return err
		}
	case relSlash == "go.sum":
		existing, err := os.ReadFile(targetPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read existing go.sum: %w", err)
		}
		data = MergeGoSum(data, existing)
	case isGoSource(relSlash):
		data = rewriteModulePath(data)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", relSlash, err)
	}
	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", relSlash, err)
	}
	return nil
}
