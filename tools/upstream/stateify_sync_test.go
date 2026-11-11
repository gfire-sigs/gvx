package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/tools/gostateify/stateify"
)

func TestTier1PrefixesMatchStateify(t *testing.T) {
	t.Parallel()
	if !slices.Equal(tier1Prefixes, stateify.Tier1Prefixes()) {
		t.Fatalf("tier1Prefixes mismatch:\ndiff_audit: %v\nstateify:   %v", tier1Prefixes, stateify.Tier1Prefixes())
	}
}

func TestSyncUpstreamRegeneratesStateifyBeforeRetag(t *testing.T) {
	t.Parallel()

	const nextSHA = "1111111111111111111111111111111111111111"
	cacheDir := t.TempDir()
	writeCachedArchiveSHA(t, cacheDir, testSHA, baseUpstream())

	repo := with(cleanRepo(),
		"go.mod", "module z.gfire.dev/gvx\n\ngo 1.27.4\n\nrequire golang.org/x/arch v0.32.0\n",
		"pkg/fd/fd_darwin.go", "package fd\n",
		"tools/gostateify/internal/testfixture/set.go", "package testfixture\n\n// +stateify savable\ntype Set struct {\n\tCount uint32\n}\n",
		"tools/gostateify/packages.txt", "pkg/erofs\ntools/gostateify/internal/testfixture\n",
	)
	root, _ := writeMainRepo(t, repo)
	writeTestFile(t, root, "tools/upstream/buildtag_allowlist.txt", "linux-only pkg/hostsyscall/\nlinux-only pkg/erofs/erofs_state_autogen.go\n")

	erofsSrc := "package erofs\n\n// +stateify savable\ntype Entry struct {\n\tLevel uint32\n}\n\nfunc F() {}\n"
	seedDir := t.TempDir()
	writeTestFile(t, seedDir, "go.mod", "module gvisor.dev/gvisor\n\ngo 1.27\n")
	writeTestFile(t, seedDir, "pkg/erofs/erofs.go", erofsSrc)
	if _, err := stateify.Run(stateify.Options{RootDir: seedDir, Packages: []string{"pkg/erofs"}, PartitionByTier: true}); err != nil {
		t.Fatalf("seed upstream erofs_state_autogen.go: %v", err)
	}
	upstreamAutogen := readTestFile(t, seedDir, "pkg/erofs/erofs_state_autogen.go")

	up := with(baseUpstream(),
		"pkg/erofs/erofs.go", erofsSrc,
		"pkg/erofs/erofs_state_autogen.go", upstreamAutogen,
	)
	writeCachedArchiveSHA(t, cacheDir, nextSHA, up)

	stdout, stderr, err := runTool(t, "-mode=sync", "-root", root, "-ref", nextSHA, "-cache-dir", cacheDir, "-offline")
	if err != nil {
		t.Fatalf("sync with stateify hook failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.Contains(stdout, "audit passed") {
		t.Fatalf("expected audit passed in stdout:\n%s", stdout)
	}

	got := readTestFile(t, root, "tools/gostateify/internal/testfixture/testfixture_state_autogen.go")
	if !strings.Contains(got, `"tools/gostateify/internal/testfixture.Set"`) || !strings.Contains(got, "SaveUint32(0, &s.Count)") {
		t.Fatalf("unexpected generated testfixture_state_autogen.go:\n%s", got)
	}

	// Because RegenerateStateify ran before RetagFiles, linux-only in buildtag_allowlist.txt remains authoritative.
	erofsAutogen := readTestFile(t, root, "pkg/erofs/erofs_state_autogen.go")
	if !strings.Contains(erofsAutogen, "//go:build linux\n") {
		t.Fatalf("expected RetagFiles linux-only rule to apply after stateify regeneration:\n%s", erofsAutogen)
	}
}

func TestSyncUpstreamDestSubdirResolvesRootPackagesFile(t *testing.T) {
	t.Parallel()

	repo := with(cleanRepo(),
		"tools/gostateify/packages.txt", "pkg/erofs\ntools/gostateify/internal/testfixture\n",
	)
	root, _ := writeMainRepo(t, repo)

	up := with(baseUpstream(),
		"pkg/erofs/erofs.go", "package erofs\n\n// +stateify savable\ntype Entry struct {\n\tSeq uint64\n}\n\nfunc F() {}\n",
	)
	archive := writeArchiveFile(t, up)

	_, stderr, err := runTool(t, "-mode=sync", "-root", root, "-dest", "staged", "-ref", testSHA, "-archive", archive, "-offline")
	if err != nil {
		t.Fatalf("sync to -dest staged failed: %v\nstderr: %s", err, stderr)
	}

	stagedAutogen := readTestFile(t, root, "staged/pkg/erofs/erofs_state_autogen.go")
	if !strings.Contains(stagedAutogen, `"pkg/erofs.Entry"`) {
		t.Fatalf("expected staged erofs_state_autogen.go to be generated from root packages.txt:\n%s", stagedAutogen)
	}
}

func TestGitSyncRegeneratesStateifyPackages(t *testing.T) {
	isolateGit(t)
	upstream, fork, _ := newFork(t)

	writeTestFile(t, upstream, "pkg/sentry/kernel/doc.go", "package kernel\n")
	sha := gitCommitAll(t, upstream, "add sentry kernel")

	runGit(t, fork, "fetch", "origin")
	runGit(t, fork, "merge", "--no-edit", sha)
	writeTestFile(t, fork, "UPSTREAM_COMMIT", sha+"\n")
	writeTestFile(t, fork, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+sha+`"}`+"\n")
	writeTestFile(t, fork, "go.mod", "module z.gfire.dev/gvx\n\ngo 1.27\n")
	writeTestFile(t, fork, "pkg/sentry/kernel/ext_xplat.go", "package kernel\n\n// +stateify savable\ntype XplatNote struct {\n\tID uint64\n}\n")
	writeTestFile(t, fork, "tools/gostateify/packages.txt", "pkg/sentry/kernel tier2\n")
	gitCommitAll(t, fork, "add xplat stateify type")

	writeTestFile(t, upstream, "pkg/log/log.go", "package log\n\nfunc Info() {}\n")
	gitCommitAll(t, upstream, "upstream 3")

	var log []string
	cfg := gitSyncConfig(t, upstream, fork, &log)
	cfg.RegenStateify = true
	if _, err := GitSync(context.Background(), cfg); err != nil {
		t.Fatalf("GitSync with RegenStateify: %v (log: %v)", err, log)
	}

	got := readTestFile(t, fork, "pkg/sentry/kernel/kernel_xplat_state_autogen.go")
	if !strings.Contains(got, `"pkg/sentry/kernel.XplatNote"`) || !strings.Contains(got, "SaveUint64(0, &x.ID)") {
		t.Fatalf("unexpected generated kernel_xplat_state_autogen.go:\n%s", got)
	}
}
