// Command upstream audits, retags, and synchronizes the gvx fork of google/gvisor.
//
// Modes follow SPEC section 2.3: audit, retag, resolve, and sync.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var errUnknownMode = errors.New("unsupported mode: must be audit, retag, restore, resolve, or sync")

var errUnknownStrategy = errors.New("unsupported strategy: must be auto, git, or archive")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "upstream tool failed: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	mode        string
	maxRatio    float64
	countFences bool
	rootDir     string
	allowlist   string
	mask        string
	destSubdir  string
	repoURL     string
	targetRef   string
	archivePath string
	cacheDir    string
	offline     bool
	strategy    string
	timeout     time.Duration
	maxFindings int
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("upstream", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.mode, "mode", "audit", "operation mode: audit, retag, resolve, or sync")
	fs.Float64Var(&o.maxRatio, "max-ratio", 0.05, "maximum allowed ratio of budgeted upstream files (0.05 is 5.0%)")
	fs.BoolVar(&o.countFences, "count-fences", false, "charge Linux-only build fences against the budget (strictest reading of SPEC 2.2)")
	fs.StringVar(&o.rootDir, "root", ".", "repository root directory")
	fs.StringVar(&o.allowlist, "allowlist", "tools/upstream/buildtag_allowlist.txt", "path to the build-tag allowlist")
	fs.StringVar(&o.mask, "mask", "tools/upstream/file_mask.txt", "path to the upstream file mask")
	fs.StringVar(&o.destSubdir, "dest", ".", "destination directory relative to root for archive sync")
	fs.StringVar(&o.repoURL, "repo", DefaultUpstreamRepoURL, "upstream gVisor Git repository URL")
	fs.StringVar(&o.targetRef, "ref", "", "40-character upstream commit SHA; audit compares against it, sync merges it")
	fs.StringVar(&o.archivePath, "archive", "", "path to a cached upstream tar.gz; overrides the cache directory")
	fs.StringVar(&o.cacheDir, "cache-dir", "", "directory for <sha>.tar.gz archives (default: per-user cache)")
	fs.BoolVar(&o.offline, "offline", false, "use cached archives only and fail when one is missing")
	fs.StringVar(&o.strategy, "strategy", "auto", "sync strategy: auto, git (SPEC 2.3 merge), or archive (overlay fallback)")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Minute, "network timeout for download, resolve, and sync modes")
	fs.IntVar(&o.maxFindings, "max-findings", 60, "audit findings to print; 0 prints all (the exit status still counts all)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}

	patches, err := LoadPatchSet(resolvePath(o.rootDir, o.allowlist))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	switch o.mode {
	case "retag":
		report, err := RetagFiles(o.rootDir, patches)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "retag complete: module_path=%d build_patches=%d formatted_generated=%d\n",
			report.ModulePath, report.Patched, report.Formatted)
		return nil
	case "audit":
		mask, err := LoadFileMask(resolvePath(o.rootDir, o.mask))
		if err != nil {
			return err
		}
		return auditMode(ctx, o, patches, mask, stdout, stderr)
	case "restore":
		mask, err := LoadFileMask(resolvePath(o.rootDir, o.mask))
		if err != nil {
			return err
		}
		return restoreMode(ctx, o, patches, mask, stdout)
	case "resolve":
		refs, err := ResolveUpstreamRefs(ctx, o.repoURL)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "go_branch=%s latest_release=%s (%s)\n", refs.GoBranchSHA, refs.ReleaseTag, refs.ReleaseTagSHA)
		return nil
	case "sync":
		mask, err := LoadFileMask(resolvePath(o.rootDir, o.mask))
		if err != nil {
			return err
		}
		return syncMode(ctx, o, patches, mask, stdout, stderr)
	default:
		return fmt.Errorf("%w: %q", errUnknownMode, o.mode)
	}
}

func (o options) archiveSource(gitDir string) ArchiveSource {
	return ArchiveSource{ArchivePath: o.archivePath, CacheDir: o.cacheDir, GitDir: gitDir, Offline: o.offline}
}

// loadAuditConfig resolves the upstream commit from -ref or UPSTREAM_COMMIT and loads its tree.
func loadAuditConfig(ctx context.Context, o options, patches *PatchSet, mask *FileMask) (AuditConfig, error) {
	sha := o.targetRef
	if sha == "" {
		commit, err := ReadUpstreamCommit(o.rootDir)
		if err != nil {
			return AuditConfig{}, err
		}
		if err := ValidateManifest(o.rootDir, commit); err != nil {
			return AuditConfig{}, err
		}
		sha = commit
	}
	sha, err := ValidateCommitSHA(sha)
	if err != nil {
		return AuditConfig{}, err
	}

	gitDir := ""
	if fork, err := IsGitFork(ctx, o.rootDir); err != nil {
		return AuditConfig{}, err
	} else if fork {
		gitDir = o.rootDir
	}
	tree, err := o.archiveSource(gitDir).Load(ctx, sha)
	if err != nil {
		return AuditConfig{}, err
	}
	return AuditConfig{
		RootDir:     o.rootDir,
		Patches:     patches,
		Mask:        mask,
		Upstream:    tree,
		MaxRatio:    o.maxRatio,
		CountFences: o.countFences,
	}, nil
}

// auditMode compares the work tree with the upstream commit from -ref or UPSTREAM_COMMIT.
func auditMode(ctx context.Context, o options, patches *PatchSet, mask *FileMask, stdout, stderr io.Writer) error {
	cfg, err := loadAuditConfig(ctx, o, patches, mask)
	if err != nil {
		return err
	}
	report, err := RunAudit(cfg)
	printReport(stdout, report, o.maxRatio)
	if err != nil {
		printViolations(stderr, err, o.maxFindings)
		return fmt.Errorf("audit failed with %d finding(s)", countErrors(err))
	}
	fmt.Fprintln(stdout, "audit passed")
	return nil
}

// restoreMode undoes build-constraint and formatting edits that the allowlist does not require,
// then re-applies the edits that it does require.
func restoreMode(ctx context.Context, o options, patches *PatchSet, mask *FileMask, stdout io.Writer) error {
	cfg, err := loadAuditConfig(ctx, o, patches, mask)
	if err != nil {
		return err
	}
	restored, err := RestoreUnrequiredEdits(cfg)
	if err != nil {
		return err
	}
	report, err := RetagFiles(o.rootDir, patches)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "restore complete: restored=%d retagged=%d formatted_generated=%d\n", restored, report.Patched, report.Formatted)
	return nil
}

func printReport(w io.Writer, r AuditReport, maxRatio float64) {
	commit := r.UpstreamCommit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	fmt.Fprintf(w, "upstream commit=%s baseline=%d go/asm files (mask-excluded=%d)\n", commit, r.UpstreamBaseline, r.MaskExcluded)
	fmt.Fprintf(w, "tier1 (additive):  files=%d\n", r.Tier1Count)
	fmt.Fprintf(w, "tier2 (siblings):  files=%d upstream-shadows=%d shadow-edits=%d\n", r.Tier2Count, r.Tier2Shadows, r.Shadow)
	fmt.Fprintf(w, "tier2 (xplat):     files=%d loc=%d shared-pkgs=%d\n", r.Tier2XplatCount, r.Tier2XplatLOC, r.Tier2SharedPkgCount)
	fmt.Fprintf(w, "tier3 (upstream):  files=%d pristine=%d format-only=%d build-expand=%d seams=%d added=%d tests-added=%d\n",
		r.Tier3Count, r.Pristine, r.Format, r.Expand, r.Seam, r.Added, r.TestsAdded)
	fmt.Fprintf(w, "tier3 linux fences=%d (machine-derived, SPEC 2.3 retag)\n", r.Fence)
	fmt.Fprintf(w, "budget: touched=%d/%d (%.2f%% of limit %.2f%%); strict with fences=%.2f%%\n",
		r.Budgeted, r.UpstreamBaseline, r.BudgetedRatio*100, maxRatio*100, r.StrictRatio*100)
	for i, f := range r.AddedFiles {
		if i == 20 {
			fmt.Fprintf(w, "  ... %d more added files\n", len(r.AddedFiles)-i)
			break
		}
		fmt.Fprintf(w, "  added: %s\n", f)
	}
}

func flattenErrors(err error) []error {
	if err == nil {
		return nil
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range multi.Unwrap() {
			out = append(out, flattenErrors(e)...)
		}
		return out
	}
	return []error{err}
}

func countErrors(err error) int { return len(flattenErrors(err)) }

func printViolations(w io.Writer, err error, limit int) {
	all := flattenErrors(err)
	for i, e := range all {
		if limit > 0 && i == limit {
			fmt.Fprintf(w, "  ... %d more findings\n", len(all)-i)
			return
		}
		fmt.Fprintf(w, "  violation: %v\n", e)
	}
}

// syncMode implements SPEC 2.3. A git fork with shared history takes the merge path.
// Every other repository takes the archive overlay and receives an explicit notice.
func syncMode(ctx context.Context, o options, patches *PatchSet, mask *FileMask, stdout, stderr io.Writer) error {
	switch o.strategy {
	case "auto", "git", "archive":
	default:
		return fmt.Errorf("%w: %q", errUnknownStrategy, o.strategy)
	}

	gitDir := ""
	if o.strategy != "archive" {
		fork, err := IsGitFork(ctx, o.rootDir)
		if err != nil {
			return err
		}
		switch {
		case fork:
			gitDir = o.rootDir
			manifest, err := GitSync(ctx, GitSyncConfig{
				RootDir:   o.rootDir,
				RemoteURL: o.repoURL,
				TargetRef: o.targetRef,
				MaxRatio:  o.maxRatio,
				Mask:      mask,
				Patches:   patches,
				Source:    o.archiveSource(""),
				Log:       func(format string, args ...any) { fmt.Fprintf(stdout, format+"\n", args...) },
			})
			if err == nil {
				fmt.Fprintf(stdout, "sync complete (git merge, uncommitted): commit=%s\n", manifest.GoBranchSHA)
				return nil
			}
			if o.strategy == "git" || !errors.Is(err, errNoSharedHistory) {
				return err
			}
			fmt.Fprintf(stderr, "note: %v\nnote: falling back to the archive overlay; a literal `git merge upstream/go` cannot work here\n", err)
		case o.strategy == "git":
			return errNotGitFork
		default:
			fmt.Fprintln(stderr, "note: repository root is not a git work tree; using the archive overlay")
		}
	}

	inPlace := filepath.Clean(cmp.Or(o.destSubdir, ".")) == "."
	var auditReport AuditReport
	var rawAuditErr error
	var auditRan bool
	manifest, err := SyncUpstream(ctx, SyncConfig{
		RootDir:     o.rootDir,
		DestSubdir:  o.destSubdir,
		RepoURL:     o.repoURL,
		TargetRef:   o.targetRef,
		MaxRatio:    o.maxRatio,
		CountFences: o.countFences,
		Audit:       inPlace,
		Mask:        mask,
		Patches:     patches,
		Source:      o.archiveSource(gitDir),
		OnAudit: func(r AuditReport, auditErr error) {
			auditReport = r
			rawAuditErr = auditErr
			auditRan = true
		},
	})
	if rawAuditErr != nil {
		printReport(stdout, auditReport, o.maxRatio)
		printViolations(stderr, rawAuditErr, o.maxFindings)
		return fmt.Errorf("audit failed with %d finding(s): %w", countErrors(rawAuditErr), rawAuditErr)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout,
		"sync complete (archive overlay): commit=%s release=%s extracted=%d merged=%d deleted=%d protected_skipped=%d excluded_skipped=%d dest=%s\n",
		manifest.GoBranchSHA[:12], manifest.ReleaseTag, manifest.ExtractedFiles, manifest.MergedFiles, manifest.DeletedFiles, manifest.ProtectedSkips, manifest.ExcludedSkips, manifest.DestDir,
	)
	if !inPlace {
		fmt.Fprintln(stdout, "run `go mod tidy`, then -mode=audit, then the five-target builds")
		return nil
	}
	if auditRan {
		printReport(stdout, auditReport, o.maxRatio)
		fmt.Fprintln(stdout, "audit passed")
	}
	fmt.Fprintln(stdout, "run `go mod tidy`, then the five-target builds")
	return nil
}

func resolvePath(rootDir, relOrAbs string) string {
	if filepath.IsAbs(relOrAbs) {
		return relOrAbs
	}
	return filepath.Join(rootDir, relOrAbs)
}
