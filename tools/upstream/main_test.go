package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMainRepo lays out a minimal repository with a pinned archive that run() can audit offline.
func writeMainRepo(t *testing.T, repo map[string]string) (root, archive string) {
	t.Helper()
	root = t.TempDir()
	for rel, body := range repo {
		writeTestFile(t, root, rel, body)
	}
	writeTestFile(t, root, "UPSTREAM_COMMIT", testSHA+"\n")
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+testSHA+`"}`)
	writeTestFile(t, root, "tools/upstream/buildtag_allowlist.txt", "linux-only pkg/hostsyscall/\n")
	writeTestFile(t, root, "tools/upstream/file_mask.txt", auditMaskText)
	archive = writeArchiveFile(t, baseUpstream())
	return root, archive
}

func runTool(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	err = run(args, &out, &errBuf)
	return out.String(), errBuf.String(), err
}

func TestRunAuditPrintsPerTierNumbers(t *testing.T) {
	t.Parallel()

	repo := with(cleanRepo(),
		"pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n",
		"pkg/kernel/helper_xplat.go", "package kernel\n\nfunc Helper() {}\n",
		"pkg/kernel/helper_xplat_test.go", "package kernel\n",
		"pkg/fd/fd_xplat.go", "package fd\n",
	)
	root, archive := writeMainRepo(t, repo)

	stdout, stderr, err := runTool(t, "-mode=audit", "-root", root, "-archive", archive, "-offline")
	if err != nil {
		t.Fatalf("run audit: %v\nstderr: %s", err, stderr)
	}
	for _, want := range []string{
		"baseline=48",
		"tier1 (additive):",
		"tier2 (siblings):",
		"tier2 (xplat):     files=2 loc=4 shared-pkgs=2",
		"tier3 (upstream):",
		"linux fences=1",
		"budget: touched=0/48",
		"audit passed",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("audit output lacks %q:\n%s", want, stdout)
		}
	}
}

func TestRunAuditFailsWithListedFindings(t *testing.T) {
	t.Parallel()

	repo := with(cleanRepo(), "pkg/kernel/kernel.go", "package kernel\n\nvar X = 1\n")
	root, archive := writeMainRepo(t, repo)

	_, stderr, err := runTool(t, "-mode=audit", "-root", root, "-archive", archive, "-offline")
	if err == nil || !strings.Contains(err.Error(), "audit failed with") {
		t.Fatalf("run audit err = %v, want an audit failure", err)
	}
	if !strings.Contains(stderr, "pkg/kernel/kernel.go") {
		t.Fatalf("stderr does not name the offending file:\n%s", stderr)
	}
}

func TestRunAuditOfflineWithoutCacheFailsClearly(t *testing.T) {
	t.Parallel()

	root, _ := writeMainRepo(t, cleanRepo())
	_, _, err := runTool(t, "-mode=audit", "-root", root, "-cache-dir", t.TempDir(), "-offline")
	if !errors.Is(err, errArchiveMissing) {
		t.Fatalf("run audit err = %v, want %v", err, errArchiveMissing)
	}
}

func TestRunAuditRefusesManifestThatDisagreesWithCommit(t *testing.T) {
	t.Parallel()

	root, archive := writeMainRepo(t, cleanRepo())
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+strings.Repeat("a", 40)+`"}`)
	if _, _, err := runTool(t, "-mode=audit", "-root", root, "-archive", archive, "-offline"); !errors.Is(err, errManifestMismatch) {
		t.Fatalf("run audit err = %v, want %v", err, errManifestMismatch)
	}
}

func TestRunRestoreThenAuditPasses(t *testing.T) {
	t.Parallel()

	repo := with(cleanRepo(),
		"pkg/kernel/kernel.go", "//go:build linux\n\npackage kernel\n",
		"pkg/hostsyscall/sys.go", "package hostsyscall\n",
	)
	root, archive := writeMainRepo(t, repo)

	if _, _, err := runTool(t, "-mode=audit", "-root", root, "-archive", archive, "-offline"); err == nil {
		t.Fatal("audit of an unfenced hostsyscall and an unlisted fence must fail")
	}
	stdout, stderr, err := runTool(t, "-mode=restore", "-root", root, "-archive", archive, "-offline")
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "restored=1 retagged=1") {
		t.Fatalf("restore output = %q, want restored=1 retagged=1", stdout)
	}
	if _, stderr, err := runTool(t, "-mode=audit", "-root", root, "-archive", archive, "-offline"); err != nil {
		t.Fatalf("audit after restore: %v\n%s", err, stderr)
	}
}

func TestRunRetagMode(t *testing.T) {
	t.Parallel()

	root, _ := writeMainRepo(t, with(cleanRepo(), "pkg/hostsyscall/sys.go", "package hostsyscall\n"))
	stdout, _, err := runTool(t, "-mode=retag", "-root", root)
	if err != nil {
		t.Fatalf("retag: %v", err)
	}
	if !strings.Contains(stdout, "build_patches=1") {
		t.Fatalf("retag output = %q", stdout)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "pkg/hostsyscall/sys.go")); !strings.HasPrefix(string(got), "//go:build linux\n") {
		t.Fatalf("sys.go = %q", got)
	}
}

func TestRunRejectsUnknownModeAndStrategy(t *testing.T) {
	t.Parallel()

	root, _ := writeMainRepo(t, cleanRepo())
	if _, _, err := runTool(t, "-mode=bogus", "-root", root); !errors.Is(err, errUnknownMode) {
		t.Fatalf("unknown mode err = %v, want %v", err, errUnknownMode)
	}
	if _, _, err := runTool(t, "-mode=sync", "-strategy=bogus", "-root", root); !errors.Is(err, errUnknownStrategy) {
		t.Fatalf("unknown strategy err = %v, want %v", err, errUnknownStrategy)
	}
	if _, _, err := runTool(t, "-mode=audit", "-root", root, "-allowlist", "missing.txt"); err == nil {
		t.Fatal("missing allowlist must fail")
	}
}

func TestSyncModeFallsBackToArchiveOverlayOutsideGit(t *testing.T) {
	t.Parallel()

	// The PROTECTed Tier 2 shadow file is gvx-owned: sync leaves it alone and the audit expects it to exist.
	root, archive := writeMainRepo(t, map[string]string{"pkg/shadow/shadow_darwin.go": "package shadow\n"})
	writeTestFile(t, root, "go.mod", "module z.gfire.dev/gvx\n\ngo 1.27.4\n\nrequire golang.org/x/arch v0.32.0\n")
	stdout, stderr, err := runTool(t, "-mode=sync", "-root", root, "-ref", testSHA, "-archive", archive, "-offline")
	if err != nil {
		t.Fatalf("sync: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stderr, "not a git work tree") {
		t.Errorf("stderr lacks the fallback notice:\n%s", stderr)
	}
	if !strings.Contains(stdout, "archive overlay") || !strings.Contains(stdout, "audit passed") {
		t.Errorf("stdout = %s", stdout)
	}
	if got := readTestFile(t, root, "pkg/hostsyscall/sys.go"); !strings.HasPrefix(got, "//go:build linux\n") {
		t.Errorf("sync did not retag: %q", got)
	}
}

func TestSyncModeGitStrategyNeedsGitWorkTree(t *testing.T) {
	t.Parallel()

	root, archive := writeMainRepo(t, nil)
	if _, _, err := runTool(t, "-mode=sync", "-strategy=git", "-root", root, "-ref", testSHA, "-archive", archive, "-offline"); !errors.Is(err, errNotGitFork) {
		t.Fatalf("sync err = %v, want %v", err, errNotGitFork)
	}
}

func TestSyncModeFallsBackWhenForkSharesNoHistory(t *testing.T) {
	isolateGit(t)
	upstream := newGitRepo(t, gitUpstreamFiles())
	gitCommitAll(t, upstream, "upstream")
	runGit(t, upstream, "branch", "-m", defaultUpstreamBranch)
	fork := newGitRepo(t, map[string]string{"README.md": "fork\n"})
	writeTestFile(t, fork, "go.mod", "module z.gfire.dev/gvx\n\ngo 1.27.4\n\nrequire golang.org/x/arch v0.32.0\n")
	writeTestFile(t, fork, "tools/upstream/buildtag_allowlist.txt", "linux-only pkg/hostsyscall/\n")
	writeTestFile(t, fork, "tools/upstream/file_mask.txt", "INCLUDE go.mod\nINCLUDE pkg/**\n")
	gitCommitAll(t, fork, "fork")

	// A real upstream archive for the fallback comes from the upstream repository's own commit.
	sha := runGit(t, upstream, "rev-parse", "HEAD")
	cache := t.TempDir()
	if _, err := (ArchiveSource{CacheDir: cache, GitDir: upstream, Offline: true}).Load(t.Context(), sha); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	stdout, stderr, err := runTool(t, "-mode=sync", "-root", fork, "-repo", upstream, "-ref", sha, "-cache-dir", cache, "-offline")
	if err == nil {
		// The upstream test tree has no go.mod, so the overlay audit may legitimately pass or fail;
		// only the strategy decision is under test here.
		_ = stdout
	}
	if !strings.Contains(stderr, "shares no git history") || !strings.Contains(stderr, "falling back to the archive overlay") {
		t.Fatalf("stderr lacks the fallback notice (err=%v):\n%s", err, stderr)
	}
}

func TestSyncModeFallbackPreservesSeamsAndRemovesDeletedFiles(t *testing.T) {
	isolateGit(t)
	upFiles := gitUpstreamFiles()
	upFiles["pkg/obsolete/old.go"] = "package obsolete\n"
	upFiles["pkg/seam/seam.go"] = "package seam\n\nfunc Top() int {\n\treturn 1\n}\n\nfunc Bottom() int {\n\treturn 10\n}\n"
	upstream := newGitRepo(t, upFiles)
	sha1 := gitCommitAll(t, upstream, "upstream 1")
	runGit(t, upstream, "branch", "-m", defaultUpstreamBranch)

	// Build an archive-imported fork with no shared git history, local Tier 3 seam edit, and pinned sha1.
	fork := newGitRepo(t, upFiles)
	writeTestFile(t, fork, "tools/upstream/buildtag_allowlist.txt", "linux-only pkg/hostsyscall/\nseam pkg/seam/seam.go\n")
	writeTestFile(t, fork, "tools/upstream/file_mask.txt", "PROTECT tools/upstream/**\nINCLUDE pkg/**\n")
	if _, err := RetagFiles(fork, mustPatchSet(t, "linux-only pkg/hostsyscall/\nseam pkg/seam/seam.go\n")); err != nil {
		t.Fatalf("RetagFiles: %v", err)
	}
	writeTestFile(t, fork, "pkg/seam/seam.go", "package seam\n\nfunc Top() int {\n\treturn 1\n}\n\nfunc Bottom() int {\n\treturn 99\n}\n")
	writeTestFile(t, fork, "UPSTREAM_COMMIT", sha1+"\n")
	writeTestFile(t, fork, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+sha1+`"}`+"\n")
	gitCommitAll(t, fork, "imported fork with seam")

	// Advance upstream: edit Top() in seam.go and delete pkg/obsolete/old.go.
	writeTestFile(t, upstream, "pkg/seam/seam.go", "package seam\n\nfunc Top() int {\n\treturn 2\n}\n\nfunc Bottom() int {\n\treturn 10\n}\n")
	if err := os.Remove(filepath.Join(upstream, "pkg/obsolete/old.go")); err != nil {
		t.Fatalf("remove old.go: %v", err)
	}
	sha2 := gitCommitAll(t, upstream, "upstream 2")

	cache := t.TempDir()
	if _, err := (ArchiveSource{CacheDir: cache, GitDir: upstream, Offline: true}).Load(t.Context(), sha1); err != nil {
		t.Fatalf("prime sha1 cache: %v", err)
	}

	stdout, stderr, err := runTool(t, "-mode=sync", "-root", fork, "-repo", upstream, "-ref", sha2, "-cache-dir", cache, "-offline", "-max-ratio=0.10")
	if err != nil {
		t.Fatalf("sync fallback failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "audit passed") {
		t.Fatalf("stdout lacks audit confirmation:\n%s", stdout)
	}
	if got := strings.TrimSpace(readTestFile(t, fork, "UPSTREAM_COMMIT")); got != sha2 {
		t.Fatalf("UPSTREAM_COMMIT = %q, want %q", got, sha2)
	}
	seam := readTestFile(t, fork, "pkg/seam/seam.go")
	if !strings.Contains(seam, "return 2") || !strings.Contains(seam, "return 99") {
		t.Fatalf("seam file did not preserve both edits:\n%s", seam)
	}
	if _, err := os.Stat(filepath.Join(fork, "pkg/obsolete/old.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted upstream file remained in fork: %v", err)
	}
}
