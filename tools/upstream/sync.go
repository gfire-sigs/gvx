package main

import (
	"bufio"
	"bytes"
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
	targetXSysUnix       = `"z.gfire.dev/gvx/internal/xsys/unix"`
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
	if suffix, ok := strings.CutPrefix(pattern, "**/"); ok {
		if !strings.Contains(suffix, "/") {
			matched, err := path.Match(suffix, path.Base(relPath))
			return err == nil && matched
		}
		for tail := relPath; ; {
			if matchMaskPattern(suffix, tail) {
				return true
			}
			var rest string
			_, rest, ok = strings.Cut(tail, "/")
			if !ok {
				return false
			}
			tail = rest
		}
	}
	if before, after, ok := strings.Cut(pattern, "/**/"); ok {
		rest, hasPrefix := strings.CutPrefix(relPath, before+"/")
		return hasPrefix && matchMaskPattern("**/"+after, rest)
	}
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		return relPath == prefix || strings.HasPrefix(relPath, prefix+"/")
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

// SyncConfig configures an upstream snapshot download and three-way masked merge.
type SyncConfig struct {
	RootDir     string
	DestSubdir  string
	RepoURL     string
	TargetRef   string
	MaxRatio    float64
	CountFences bool
	Audit       bool
	Mask        *FileMask
	// Patches, when set, runs RetagFiles on the destination after extraction.
	Patches *PatchSet
	Source  ArchiveSource
	// OnAudit receives the audit report when an in-place sync runs RunAudit.
	OnAudit func(AuditReport, error)
}

// SyncManifest records the result of an upstream sync.
type SyncManifest struct {
	GoBranchSHA    string   `json:"go_branch_sha"`
	ReleaseTag     string   `json:"release_tag"`
	ReleaseTagSHA  string   `json:"release_tag_sha"`
	ExtractedFiles int      `json:"extracted_files"`
	MergedFiles    int      `json:"merged_files,omitempty"`
	DeletedFiles   int      `json:"deleted_files,omitempty"`
	ProtectedSkips int      `json:"protected_skips"`
	ExcludedSkips  int      `json:"excluded_skips"`
	Conflicts      []string `json:"conflicts,omitempty"`
	DestDir        string   `json:"dest_dir"`
	Strategy       string   `json:"strategy,omitempty"`
}

// Sync strategy names recorded in the manifest.
const (
	StrategyArchive = "archive"
	StrategyGit     = "git"
)

// SyncUpstream resolves the upstream commit, merges masked files into DestSubdir,
// audits in-place changes against the target tree, and records UPSTREAM_COMMIT.
func SyncUpstream(ctx context.Context, cfg SyncConfig) (SyncManifest, error) {
	cfg.RootDir = cmp.Or(cfg.RootDir, ".")
	cfg.DestSubdir = cmp.Or(cfg.DestSubdir, ".")
	inPlace := filepath.Clean(cfg.DestSubdir) == "."

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

	var oldTree *UpstreamTree
	if inPlace {
		oldSHA, commitErr := ReadUpstreamCommit(cfg.RootDir)
		if commitErr != nil && !errors.Is(commitErr, os.ErrNotExist) {
			return SyncManifest{}, commitErr
		}
		if commitErr == nil {
			if oldSHA == refs.GoBranchSHA {
				oldTree = tree
			} else {
				baseSource := cfg.Source
				baseSource.ArchivePath = ""
				oldTree, err = baseSource.Load(ctx, oldSHA)
				if err != nil {
					return SyncManifest{}, fmt.Errorf("load base upstream commit %s: %w", oldSHA, err)
				}
			}
		}
	}

	destRoot := filepath.Clean(filepath.Join(cfg.RootDir, cfg.DestSubdir))
	if err := os.MkdirAll(destRoot, 0o755); err != nil {
		return SyncManifest{}, fmt.Errorf("mkdir %s: %w", destRoot, err)
	}
	manifest, err := mergeMaskedTree(ctx, oldTree, tree, destRoot, cfg.Mask, cfg.Patches)
	if err != nil {
		return SyncManifest{}, err
	}
	manifest.GoBranchSHA = refs.GoBranchSHA
	manifest.ReleaseTag = refs.ReleaseTag
	manifest.ReleaseTagSHA = refs.ReleaseTagSHA
	manifest.DestDir = destRoot
	manifest.Strategy = StrategyArchive

	if len(manifest.Conflicts) > 0 {
		return manifest, fmt.Errorf(
			"%w: resolve these files, then run -mode=retag and -mode=audit -ref=%s:\n%s",
			errMergeConflicts, refs.GoBranchSHA, strings.Join(manifest.Conflicts, "\n"),
		)
	}

	if cfg.Patches != nil {
		if _, err := RetagFiles(destRoot, cfg.Patches); err != nil {
			return manifest, fmt.Errorf("retag after extraction: %w", err)
		}
	}
	if inPlace && (cfg.Audit || cfg.MaxRatio > 0) {
		report, auditErr := RunAudit(AuditConfig{
			RootDir:     cfg.RootDir,
			Patches:     cfg.Patches,
			Mask:        cfg.Mask,
			Upstream:    tree,
			MaxRatio:    cfg.MaxRatio,
			CountFences: cfg.CountFences,
		})
		if cfg.OnAudit != nil {
			cfg.OnAudit(report, auditErr)
		}
		if auditErr != nil {
			return manifest, fmt.Errorf("audit merged tree: %w", auditErr)
		}
	}
	if inPlace {
		if err := WriteSyncRecord(cfg.RootDir, manifest); err != nil {
			return manifest, err
		}
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
	return mergeMaskedTree(context.Background(), nil, tree, destRoot, mask, nil)
}

func mergeMaskedTree(ctx context.Context, oldTree, newTree *UpstreamTree, destRoot string, mask *FileMask, patches *PatchSet) (_ SyncManifest, err error) {
	var manifest SyncManifest
	var tmpDir string
	defer func() {
		if tmpDir != "" {
			err = errors.Join(err, os.RemoveAll(tmpDir))
		}
	}()
	getTmpDir := func() (string, error) {
		if tmpDir != "" {
			return tmpDir, nil
		}
		d, mkErr := os.MkdirTemp("", "gvx-upstream-merge-*")
		if mkErr != nil {
			return "", fmt.Errorf("create merge temp directory: %w", mkErr)
		}
		tmpDir = d
		return tmpDir, nil
	}

	paths := make([]string, 0, len(newTree.Files))
	for rel := range newTree.Files {
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
		if err := mergeSingleFile(ctx, getTmpDir, oldTree, newTree.Files[rel], destRoot, rel, patches, &manifest); err != nil {
			return SyncManifest{}, err
		}
	}

	if oldTree != nil {
		oldPaths := make([]string, 0, len(oldTree.Files))
		for rel := range oldTree.Files {
			oldPaths = append(oldPaths, rel)
		}
		slices.Sort(oldPaths)
		for _, rel := range oldPaths {
			if _, inNew := newTree.Files[rel]; inNew {
				continue
			}
			decision := MaskInclude
			if mask != nil {
				decision = mask.Decide(rel)
			}
			if decision != MaskInclude || ClassifyFile(rel) != Tier3Upstream {
				continue
			}
			if err := removeDeletedUpstreamFile(oldTree.Files[rel], destRoot, rel, patches, &manifest); err != nil {
				return SyncManifest{}, err
			}
		}
	}
	slices.Sort(manifest.Conflicts)
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

func resolveDestTarget(destRoot, relSlash string) (string, error) {
	targetPath := filepath.Join(destRoot, filepath.FromSlash(relSlash))
	relCheck, err := filepath.Rel(destRoot, targetPath)
	if err != nil || strings.HasPrefix(filepath.ToSlash(relCheck), "../") {
		return "", fmt.Errorf("%w: %s escapes %s", errUnsafeArchivePath, relSlash, destRoot)
	}
	return targetPath, nil
}

func writeTargetFile(targetPath, relSlash string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", relSlash, err)
	}
	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", relSlash, err)
	}
	return nil
}

func rewriteIfGo(relSlash string, raw []byte) []byte {
	if isGoSource(relSlash) {
		return rewriteModulePath(raw)
	}
	return raw
}

func mergeSingleFile(ctx context.Context, getTmpDir func() (string, error), oldTree *UpstreamTree, newRaw []byte, destRoot, relSlash string, patches *PatchSet, manifest *SyncManifest) error {
	targetPath, err := resolveDestTarget(destRoot, relSlash)
	if err != nil {
		return err
	}

	switch relSlash {
	case "go.mod":
		existing, readErr := os.ReadFile(targetPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("read existing go.mod: %w", readErr)
		}
		merged, mergeErr := MergeGoMod(newRaw, existing)
		if mergeErr != nil {
			return mergeErr
		}
		if err := writeTargetFile(targetPath, relSlash, merged); err != nil {
			return err
		}
		manifest.ExtractedFiles++
		return nil
	case "go.sum":
		existing, readErr := os.ReadFile(targetPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("read existing go.sum: %w", readErr)
		}
		merged := MergeGoSum(newRaw, existing)
		if err := writeTargetFile(targetPath, relSlash, merged); err != nil {
			return err
		}
		manifest.ExtractedFiles++
		return nil
	}

	if oldTree == nil {
		if err := writeTargetFile(targetPath, relSlash, rewriteIfGo(relSlash, newRaw)); err != nil {
			return err
		}
		manifest.ExtractedFiles++
		return nil
	}

	theirs, _, _, _, err := retagSourceBytes(relSlash, newRaw, patches)
	if err != nil {
		return err
	}
	ours, readErr := os.ReadFile(targetPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read local %s: %w", relSlash, readErr)
	}
	if errors.Is(readErr, os.ErrNotExist) {
		if err := writeTargetFile(targetPath, relSlash, theirs); err != nil {
			return err
		}
		manifest.ExtractedFiles++
		return nil
	}

	oldRaw, inOld := oldTree.Files[relSlash]
	if !inOld {
		if bytes.Equal(ours, theirs) {
			manifest.ExtractedFiles++
			return nil
		}
		merged, conflicted, mergeErr := mergeThreeWay(ctx, getTmpDir, ours, nil, theirs)
		if mergeErr != nil {
			return fmt.Errorf("merge %s: %w", relSlash, mergeErr)
		}
		if err := writeTargetFile(targetPath, relSlash, merged); err != nil {
			return err
		}
		if conflicted {
			manifest.Conflicts = append(manifest.Conflicts, relSlash)
			return nil
		}
		manifest.MergedFiles++
		manifest.ExtractedFiles++
		return nil
	}

	base, _, _, _, err := retagSourceBytes(relSlash, oldRaw, patches)
	if err != nil {
		return err
	}
	rawBase := rewriteIfGo(relSlash, oldRaw)
	if bytes.Equal(ours, base) || bytes.Equal(ours, rawBase) {
		if err := writeTargetFile(targetPath, relSlash, theirs); err != nil {
			return err
		}
		manifest.ExtractedFiles++
		return nil
	}
	if bytes.Equal(base, theirs) {
		return nil
	}

	merged, conflicted, err := mergeThreeWay(ctx, getTmpDir, ours, base, theirs)
	if err != nil {
		return fmt.Errorf("merge %s: %w", relSlash, err)
	}
	if err := writeTargetFile(targetPath, relSlash, merged); err != nil {
		return err
	}
	if conflicted {
		manifest.Conflicts = append(manifest.Conflicts, relSlash)
		return nil
	}
	manifest.MergedFiles++
	manifest.ExtractedFiles++
	return nil
}

func removeDeletedUpstreamFile(oldRaw []byte, destRoot, relSlash string, patches *PatchSet, manifest *SyncManifest) error {
	targetPath, err := resolveDestTarget(destRoot, relSlash)
	if err != nil {
		return err
	}
	ours, readErr := os.ReadFile(targetPath)
	if errors.Is(readErr, os.ErrNotExist) {
		return nil
	}
	if readErr != nil {
		return fmt.Errorf("read local %s: %w", relSlash, readErr)
	}
	base, _, _, _, err := retagSourceBytes(relSlash, oldRaw, patches)
	if err != nil {
		return err
	}
	rawBase := rewriteIfGo(relSlash, oldRaw)
	if !bytes.Equal(ours, base) && !bytes.Equal(ours, rawBase) {
		manifest.Conflicts = append(manifest.Conflicts, relSlash)
		return nil
	}
	if err := os.Remove(targetPath); err != nil {
		return fmt.Errorf("remove deleted upstream file %s: %w", relSlash, err)
	}
	pruneEmptyParents(destRoot, filepath.Dir(targetPath))
	manifest.DeletedFiles++
	return nil
}

func pruneEmptyParents(destRoot, dir string) {
	rootClean := filepath.Clean(destRoot)
	for cur := filepath.Clean(dir); cur != rootClean && cur != "." && cur != string(filepath.Separator); cur = filepath.Dir(cur) {
		if err := os.Remove(cur); err != nil {
			return
		}
	}
}

func mergeThreeWay(ctx context.Context, getTmpDir func() (string, error), ours, base, theirs []byte) ([]byte, bool, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return formatFallbackConflict(ours, base, theirs), true, nil
	}
	dir, err := getTmpDir()
	if err != nil {
		return nil, false, err
	}
	oursPath := filepath.Join(dir, "ours")
	basePath := filepath.Join(dir, "base")
	theirsPath := filepath.Join(dir, "theirs")
	for _, input := range []struct {
		path string
		data []byte
	}{
		{oursPath, ours},
		{basePath, base},
		{theirsPath, theirs},
	} {
		if err := os.WriteFile(input.path, input.data, 0o600); err != nil {
			return nil, false, fmt.Errorf("write merge input %s: %w", filepath.Base(input.path), err)
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "merge-file", "-p", "-L", "ours", "-L", "base", "-L", "theirs", oursPath, basePath, theirsPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		return stdout.Bytes(), false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code >= 1 && code <= 127 {
			return stdout.Bytes(), true, nil
		}
	}
	return nil, false, fmt.Errorf("git merge-file: %w: %s", err, strings.TrimSpace(stderr.String()))
}

func formatFallbackConflict(ours, base, theirs []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("<<<<<<< ours\n")
	buf.Write(ours)
	if len(ours) > 0 && ours[len(ours)-1] != '\n' {
		buf.WriteByte('\n')
	}
	if len(base) > 0 {
		buf.WriteString("||||||| base\n")
		buf.Write(base)
		if base[len(base)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	buf.WriteString("=======\n")
	buf.Write(theirs)
	if len(theirs) > 0 && theirs[len(theirs)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(">>>>>>> theirs\n")
	return buf.Bytes()
}
