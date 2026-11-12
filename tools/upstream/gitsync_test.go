package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// isolateGit pins identity and configuration so the tests never read the developer's git setup.
// It cannot run in parallel tests because it sets environment variables.
func isolateGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.com")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := git(context.Background(), dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return out
}

func gitCommitAll(t *testing.T, dir, msg string) string {
	t.Helper()
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-q", "-m", msg)
	return runGit(t, dir, "rev-parse", "HEAD")
}

func newGitRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	for rel, body := range files {
		writeTestFile(t, dir, rel, body)
	}
	return dir
}

const gitUpstreamKernel = "package kernel\n\nimport _ \"gvisor.dev/gvisor/pkg/log\"\n"

func gitUpstreamFiles() map[string]string {
	files := map[string]string{
		"pkg/kernel/kernel.go":   gitUpstreamKernel,
		"pkg/hostsyscall/sys.go": "package hostsyscall\n",
		"pkg/log/log.go":         "package log\n",
	}
	for i := range 40 {
		files[fmt.Sprintf("pkg/filler/f%02d.go", i)] = "package filler\n"
	}
	return files
}

// newFork creates an upstream repository and a fork that shares its history.
// The fork carries the gvx module path and the Linux fence, as a synced tree does.
func newFork(t *testing.T) (upstream, fork, sha1 string) {
	t.Helper()
	upstream = newGitRepo(t, gitUpstreamFiles())
	sha1 = gitCommitAll(t, upstream, "upstream 1")

	fork = filepath.Join(t.TempDir(), "fork")
	runGit(t, filepath.Dir(fork), "clone", "-q", upstream, fork)
	writeTestFile(t, fork, "pkg/kernel/kernel.go", strings.ReplaceAll(gitUpstreamKernel, upstreamModulePath, targetModulePath))
	writeTestFile(t, fork, "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n")
	writeTestFile(t, fork, "UPSTREAM_COMMIT", sha1+"\n")
	writeTestFile(t, fork, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+sha1+`"}`+"\n")
	gitCommitAll(t, fork, "fork adjustments")
	return upstream, fork, sha1
}

func gitSyncConfig(t *testing.T, upstream, fork string, log *[]string) GitSyncConfig {
	t.Helper()
	mask, err := ParseFileMaskReader(strings.NewReader("INCLUDE pkg/**\n"))
	if err != nil {
		t.Fatal(err)
	}
	return GitSyncConfig{
		RootDir:   fork,
		RemoteURL: upstream,
		Branch:    "main",
		MaxRatio:  0.5,
		Mask:      mask,
		Patches:   mustPatchSet(t, "linux-only pkg/hostsyscall/\n"),
		Source:    ArchiveSource{CacheDir: t.TempDir(), Offline: true},
		Log:       func(format string, args ...any) { *log = append(*log, fmt.Sprintf(format, args...)) },
	}
}

func TestGitSyncRunsTheSevenStepProcedure(t *testing.T) {
	isolateGit(t)
	upstream, fork, sha1 := newFork(t)

	writeTestFile(t, upstream, "pkg/log/log.go", "package log\n\nfunc Warn() {}\n")
	writeTestFile(t, upstream, "pkg/log/extra.go", "package log\n\nimport _ \"gvisor.dev/gvisor/pkg/kernel\"\n")
	sha2 := gitCommitAll(t, upstream, "upstream 2")

	var log []string
	manifest, err := GitSync(context.Background(), gitSyncConfig(t, upstream, fork, &log))
	if err != nil {
		t.Fatalf("GitSync: %v (log: %v)", err, log)
	}
	if manifest.GoBranchSHA != sha2 || manifest.Strategy != StrategyGit {
		t.Fatalf("manifest = %+v, want commit %s and strategy git", manifest, sha2)
	}
	if len(log) != 7 {
		t.Fatalf("logged %d steps, want 7: %v", len(log), log)
	}
	for i, line := range log {
		if want := fmt.Sprintf("step %d:", i+1); !strings.HasPrefix(line, want) {
			t.Errorf("log[%d] = %q, want prefix %q", i, line, want)
		}
	}

	if got := strings.TrimSpace(readTestFile(t, fork, "UPSTREAM_COMMIT")); got != sha2 || got == sha1 {
		t.Fatalf("UPSTREAM_COMMIT = %q, want %q", got, sha2)
	}
	if err := ValidateManifest(fork, sha2); err != nil {
		t.Fatalf("ValidateManifest: %v", err)
	}
	if got := readTestFile(t, fork, "pkg/log/extra.go"); !strings.Contains(got, `"z.gfire.dev/gvx/pkg/kernel"`) {
		t.Fatalf("retag did not rewrite the merged file: %q", got)
	}
	if got := readTestFile(t, fork, "pkg/log/log.go"); !strings.Contains(got, "func Warn()") {
		t.Fatalf("merge did not bring upstream changes: %q", got)
	}
	// --no-commit leaves the merge pending for review.
	if _, err := os.Stat(filepath.Join(fork, ".git", "MERGE_HEAD")); err != nil {
		t.Fatalf("merge is not pending: %v", err)
	}
	if head := runGit(t, fork, "rev-parse", "HEAD"); head == sha2 {
		t.Fatal("GitSync committed the merge")
	}
}

func TestGitSyncRegistersUpstreamRemoteOnce(t *testing.T) {
	isolateGit(t)
	upstream, fork, _ := newFork(t)
	var log []string
	cfg := gitSyncConfig(t, upstream, fork, &log)

	if _, err := GitSync(context.Background(), cfg); err != nil {
		t.Fatalf("first GitSync: %v", err)
	}
	if got := runGit(t, fork, "remote", "get-url", upstreamRemoteName); got != upstream {
		t.Fatalf("remote url = %q, want %q", got, upstream)
	}
	if !strings.Contains(log[0], "registered") {
		t.Fatalf("step 1 log = %q, want a registration", log[0])
	}
}

func TestGitSyncReportsNoSharedHistory(t *testing.T) {
	isolateGit(t)
	upstream := newGitRepo(t, gitUpstreamFiles())
	gitCommitAll(t, upstream, "upstream 1")
	fork := newGitRepo(t, map[string]string{"pkg/kernel/kernel.go": "package kernel\n"})
	gitCommitAll(t, fork, "unrelated import")

	var log []string
	_, err := GitSync(context.Background(), gitSyncConfig(t, upstream, fork, &log))
	if !errors.Is(err, errNoSharedHistory) {
		t.Fatalf("GitSync err = %v, want %v", err, errNoSharedHistory)
	}
}

func TestGitSyncRefusesDirtyTree(t *testing.T) {
	isolateGit(t)
	upstream, fork, _ := newFork(t)
	writeTestFile(t, fork, "pkg/kernel/kernel.go", "package kernel\n\nvar Dirty = 1\n")

	var log []string
	if _, err := GitSync(context.Background(), gitSyncConfig(t, upstream, fork, &log)); !errors.Is(err, errDirtyTree) {
		t.Fatalf("GitSync err = %v, want %v", err, errDirtyTree)
	}
}

func TestGitSyncLeavesConflictsForTheMaintainer(t *testing.T) {
	isolateGit(t)
	upstream, fork, sha1 := newFork(t)
	writeTestFile(t, upstream, "pkg/log/log.go", "package log\n\nvar Upstream = 1\n")
	gitCommitAll(t, upstream, "upstream edit")
	writeTestFile(t, fork, "pkg/log/log.go", "package log\n\nvar Fork = 1\n")
	gitCommitAll(t, fork, "fork edit")

	var log []string
	cfg := gitSyncConfig(t, upstream, fork, &log)
	cfg.Patches = mustPatchSet(t, "linux-only pkg/hostsyscall/\nseam pkg/log/log.go\n")
	_, err := GitSync(context.Background(), cfg)
	if !errors.Is(err, errMergeConflicts) || !strings.Contains(err.Error(), "pkg/log/log.go") {
		t.Fatalf("GitSync err = %v, want %v naming the conflicted file", err, errMergeConflicts)
	}
	if got := strings.TrimSpace(readTestFile(t, fork, "UPSTREAM_COMMIT")); got != sha1 {
		t.Fatalf("UPSTREAM_COMMIT = %q, want old commit %q while conflicts are open", got, sha1)
	}
}

func TestGitSyncAuditFailureKeepsOldCommit(t *testing.T) {
	isolateGit(t)
	upstream, fork, sha1 := newFork(t)
	// A stale allowlist rule makes the post-merge audit fail.
	writeTestFile(t, upstream, "pkg/log/log.go", "package log\n\nfunc Warn() {}\n")
	gitCommitAll(t, upstream, "upstream 2")

	var log []string
	cfg := gitSyncConfig(t, upstream, fork, &log)
	cfg.Patches = mustPatchSet(t, "linux-only pkg/hostsyscall/\nlinux-only pkg/nothing/\n")
	_, err := GitSync(context.Background(), cfg)
	if !errors.Is(err, errStaleRule) {
		t.Fatalf("GitSync err = %v, want %v", err, errStaleRule)
	}
	if got := strings.TrimSpace(readTestFile(t, fork, "UPSTREAM_COMMIT")); got != sha1 {
		t.Fatalf("UPSTREAM_COMMIT = %q, want unchanged %q", got, sha1)
	}
}

func TestIsGitForkRequiresWorkTreeTopLevel(t *testing.T) {
	isolateGit(t)

	plain := t.TempDir()
	if fork, err := IsGitFork(context.Background(), plain); err != nil || fork {
		t.Fatalf("IsGitFork(plain dir) = %v, %v; want false", fork, err)
	}
	repo := newGitRepo(t, map[string]string{"a.txt": "x"})
	if fork, err := IsGitFork(context.Background(), repo); err != nil || !fork {
		t.Fatalf("IsGitFork(repo) = %v, %v; want true", fork, err)
	}
	sub := filepath.Join(repo, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if fork, err := IsGitFork(context.Background(), sub); err != nil || fork {
		t.Fatalf("IsGitFork(subdirectory) = %v, %v; want false", fork, err)
	}
}

func TestArchiveSourceBuildsArchiveFromLocalGit(t *testing.T) {
	isolateGit(t)
	repo := newGitRepo(t, gitUpstreamFiles())
	sha := gitCommitAll(t, repo, "c1")

	cache := t.TempDir()
	tree, err := ArchiveSource{CacheDir: cache, GitDir: repo, Offline: true}.Load(context.Background(), sha)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(tree.Files["pkg/kernel/kernel.go"]) != gitUpstreamKernel {
		t.Fatalf("kernel.go = %q", tree.Files["pkg/kernel/kernel.go"])
	}
	if _, err := os.Stat(filepath.Join(cache, sha+".tar.gz")); err != nil {
		t.Fatalf("git archive was not cached: %v", err)
	}

	missing := strings.Repeat("d", 40)
	_, err = ArchiveSource{CacheDir: t.TempDir(), GitDir: repo, Offline: true}.Load(context.Background(), missing)
	if !errors.Is(err, errArchiveMissing) {
		t.Fatalf("Load of an absent commit err = %v, want %v", err, errArchiveMissing)
	}
}

// readManifestFile parses tools/upstream/sync_manifest.json of the fork.
func readManifestFile(t *testing.T, fork string) SyncManifest {
	t.Helper()
	var m SyncManifest
	if err := json.Unmarshal([]byte(readTestFile(t, fork, "tools/upstream/sync_manifest.json")), &m); err != nil {
		t.Fatalf("parse sync_manifest.json: %v", err)
	}
	return m
}

func TestGitSyncRecordsNewestReleaseTagOfUpstream(t *testing.T) {
	isolateGit(t)
	upstream, fork, _ := newFork(t)
	writeTestFile(t, upstream, "pkg/log/log.go", "package log\n\nfunc Warn() {}\n")
	gitCommitAll(t, upstream, "upstream 2")
	runGit(t, upstream, "tag", "release-20260101.2")
	tagSHA := runGit(t, upstream, "rev-parse", "HEAD")
	runGit(t, upstream, "tag", "release-20260101.10")

	var log []string
	manifest, err := GitSync(context.Background(), gitSyncConfig(t, upstream, fork, &log))
	if err != nil {
		t.Fatalf("GitSync: %v (log: %v)", err, log)
	}
	if manifest.ReleaseTag != "release-20260101.10" || manifest.ReleaseTagSHA != tagSHA {
		t.Errorf("manifest release = %q %q, want release-20260101.10 %s", manifest.ReleaseTag, manifest.ReleaseTagSHA, tagSHA)
	}
	if got := readManifestFile(t, fork); got.ReleaseTag != "release-20260101.10" {
		t.Errorf("sync_manifest.json release_tag = %q, want release-20260101.10", got.ReleaseTag)
	}
}

func TestGitSyncPreservesReleaseTagWhenUpstreamHasNone(t *testing.T) {
	isolateGit(t)
	upstream, fork, sha1 := newFork(t)
	writeTestFile(t, fork, "tools/upstream/sync_manifest.json",
		`{"go_branch_sha": "`+sha1+`", "release_tag": "release-20250101.3", "release_tag_sha": "`+sha1+`"}`+"\n")
	gitCommitAll(t, fork, "record release tag")
	writeTestFile(t, upstream, "pkg/log/log.go", "package log\n\nfunc Warn() {}\n")
	gitCommitAll(t, upstream, "upstream 2")

	var log []string
	if _, err := GitSync(context.Background(), gitSyncConfig(t, upstream, fork, &log)); err != nil {
		t.Fatalf("GitSync: %v (log: %v)", err, log)
	}
	got := readManifestFile(t, fork)
	if got.ReleaseTag != "release-20250101.3" || got.ReleaseTagSHA != sha1 {
		t.Errorf("sync_manifest.json release = %q %q, want the previous tag release-20250101.3 %s", got.ReleaseTag, got.ReleaseTagSHA, sha1)
	}
}
