package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	upstreamRemoteName    = "upstream"
	defaultUpstreamBranch = "go"
)

var (
	errNotGitFork       = errors.New("repository root is not the top level of a git work tree")
	errNoSharedHistory  = errors.New("repository shares no git history with upstream/go")
	errDirtyTree        = errors.New("git work tree has uncommitted changes; commit or stash them before merging")
	errMergeConflicts   = errors.New("git merge stopped with conflicts")
	errGitRefNotFetched = errors.New("upstream commit is missing after fetch")
)

// GitSyncConfig configures the SPEC section 2.3 procedure for a git fork of google/gvisor.
type GitSyncConfig struct {
	RootDir string
	// RemoteURL is registered as the "upstream" remote when no such remote exists.
	RemoteURL string
	// Branch is the upstream branch to merge. Empty selects "go".
	Branch string
	// TargetRef optionally pins the commit to merge instead of the branch tip.
	TargetRef            string
	MaxRatio             float64
	Mask                 *FileMask
	Patches              *PatchSet
	RegenStateify        bool
	StateifyPackagesFile string
	Source               ArchiveSource
	// Log receives one line per completed step. Nil discards them.
	Log func(format string, args ...any)
}

func (c GitSyncConfig) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	}
}

// git runs one git command in dir and returns trimmed standard output.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(stdout.String()), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// IsGitFork reports whether root is the top level of a git work tree.
func IsGitFork(ctx context.Context, root string) (bool, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return false, nil
	}
	top, err := git(ctx, root, "rev-parse", "--show-toplevel")
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		// git prints "not a git repository" with exit status 128.
		if strings.Contains(err.Error(), "not a git repository") {
			return false, nil
		}
		return false, err
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", root, err)
	}
	got, err := filepath.EvalSymlinks(top)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", top, err)
	}
	return got == want, nil
}

// GitSync runs the seven documented steps against a git fork.
//
//  1. Register the upstream remote.
//  2. Fetch the upstream branch.
//  3. Verify the diff budget of the current tree against UPSTREAM_COMMIT.
//  4. Merge upstream without committing.
//  5. Retag allowlisted files.
//  6. Audit the merged tree against the merged upstream commit.
//  7. Record the merged commit in UPSTREAM_COMMIT.
//
// It returns errNoSharedHistory when the fork was created by importing an archive. The
// caller then falls back to the archive overlay. A conflicted merge stays in the work
// tree so the maintainer can resolve it.
func GitSync(ctx context.Context, cfg GitSyncConfig) (SyncManifest, error) {
	branch := cmp.Or(cfg.Branch, defaultUpstreamBranch)

	if _, err := git(ctx, cfg.RootDir, "remote", "get-url", upstreamRemoteName); err != nil {
		if _, addErr := git(ctx, cfg.RootDir, "remote", "add", upstreamRemoteName, cfg.RemoteURL); addErr != nil {
			return SyncManifest{}, fmt.Errorf("register upstream remote: %w", addErr)
		}
		cfg.logf("step 1: registered remote %s -> %s", upstreamRemoteName, cfg.RemoteURL)
	} else {
		cfg.logf("step 1: remote %s already registered", upstreamRemoteName)
	}

	if _, err := git(ctx, cfg.RootDir, "fetch", upstreamRemoteName, branch); err != nil {
		return SyncManifest{}, fmt.Errorf("fetch upstream %s: %w", branch, err)
	}
	target, err := resolveMergeTarget(ctx, cfg, branch)
	if err != nil {
		return SyncManifest{}, err
	}
	cfg.logf("step 2: fetched %s/%s at %s", upstreamRemoteName, branch, target)

	if _, err := git(ctx, cfg.RootDir, "merge-base", "HEAD", target); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return SyncManifest{}, fmt.Errorf("%w (%s)", errNoSharedHistory, target)
		}
		return SyncManifest{}, err
	}
	if dirty, err := git(ctx, cfg.RootDir, "status", "--porcelain"); err != nil {
		return SyncManifest{}, err
	} else if dirty != "" {
		return SyncManifest{}, errDirtyTree
	}

	if err := auditAgainst(ctx, cfg, ""); err != nil {
		return SyncManifest{}, fmt.Errorf("step 3: budget of current tree: %w", err)
	}
	cfg.logf("step 3: current tree is within the diff budget")

	if _, err := git(ctx, cfg.RootDir, "merge", "--no-commit", "--no-ff", target); err != nil {
		conflicts, listErr := git(ctx, cfg.RootDir, "diff", "--name-only", "--diff-filter=U")
		if listErr != nil {
			return SyncManifest{}, errors.Join(err, listErr)
		}
		return SyncManifest{}, fmt.Errorf("%w: resolve these files, then run ./scripts/gostateify.sh, -mode=retag, and -mode=audit -ref=%s:\n%s", errMergeConflicts, target, conflicts)
	}
	cfg.logf("step 4: merged %s without committing", target)

	if cfg.RegenStateify {
		if _, err := RegenerateStateify(cfg.RootDir, cfg.RootDir, cfg.StateifyPackagesFile); err != nil {
			return SyncManifest{}, fmt.Errorf("step 5: regenerate stateify: %w", err)
		}
	}
	if _, err := RetagFiles(cfg.RootDir, cfg.Patches); err != nil {
		return SyncManifest{}, fmt.Errorf("step 5: retag: %w", err)
	}
	cfg.logf("step 5: regenerated stateify and retagged allowlisted files")

	if err := auditAgainst(ctx, cfg, target); err != nil {
		return SyncManifest{}, fmt.Errorf("step 6: audit of merged tree: %w", err)
	}
	cfg.logf("step 6: audit passed")

	manifest := SyncManifest{
		GoBranchSHA: target,
		DestDir:     cfg.RootDir,
		Strategy:    StrategyGit,
	}
	manifest.ReleaseTag, manifest.ReleaseTagSHA = releaseTagFor(ctx, cfg)
	if err := WriteSyncRecord(cfg.RootDir, manifest); err != nil {
		return SyncManifest{}, fmt.Errorf("step 7: %w", err)
	}
	cfg.logf("step 7: recorded %s in UPSTREAM_COMMIT", target)
	return manifest, nil
}

// releaseTagFor returns the release tag and its commit for the sync manifest.
// AGENTS.md derives the PATCH field of the release version from the tag, so the
// manifest must never lose it. A sync of the branch tip asks the upstream remote
// for the newest release-* tag, as the archive sync does. A pinned TargetRef, or
// a remote that does not answer, keeps the values that the manifest holds now.
func releaseTagFor(ctx context.Context, cfg GitSyncConfig) (tag, sha string) {
	if cfg.TargetRef == "" {
		out, err := git(ctx, cfg.RootDir, "ls-remote", upstreamRemoteName, "refs/tags/release-*")
		if err == nil {
			if refs, parseErr := parseLsRemoteOutput(out); parseErr == nil && refs.ReleaseTag != "" {
				return refs.ReleaseTag, refs.ReleaseTagSHA
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(cfg.RootDir, "tools", "upstream", "sync_manifest.json"))
	if err != nil {
		return "", ""
	}
	var previous SyncManifest
	if json.Unmarshal(raw, &previous) != nil {
		return "", ""
	}
	return previous.ReleaseTag, previous.ReleaseTagSHA
}

// resolveMergeTarget returns the full commit SHA to merge.
func resolveMergeTarget(ctx context.Context, cfg GitSyncConfig, branch string) (string, error) {
	spec := "refs/remotes/" + upstreamRemoteName + "/" + branch + "^{commit}"
	if cfg.TargetRef != "" {
		sha, err := ValidateCommitSHA(cfg.TargetRef)
		if err != nil {
			return "", err
		}
		spec = sha + "^{commit}"
	}
	sha, err := git(ctx, cfg.RootDir, "rev-parse", "--verify", spec)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", errGitRefNotFetched, spec, err)
	}
	return ValidateCommitSHA(sha)
}

// auditAgainst audits the work tree against sha, or against UPSTREAM_COMMIT when sha is empty.
func auditAgainst(ctx context.Context, cfg GitSyncConfig, sha string) error {
	if sha == "" {
		var err error
		if sha, err = ReadUpstreamCommit(cfg.RootDir); err != nil {
			return err
		}
	}
	src := cfg.Source
	src.GitDir = cfg.RootDir
	tree, err := src.Load(ctx, sha)
	if err != nil {
		return err
	}
	_, err = RunAudit(AuditConfig{
		RootDir:  cfg.RootDir,
		Patches:  cfg.Patches,
		Mask:     cfg.Mask,
		Upstream: tree,
		MaxRatio: cfg.MaxRatio,
	})
	return err
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
