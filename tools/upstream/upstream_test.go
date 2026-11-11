package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testSHA = "0d2072ab24130458e928ea0a78b363a60705e433"

func TestClassifyFilePartitionsThreeIsolationTiers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want IsolationTier
	}{
		{name: "tier1 cli runner", path: "cmd/rungv/main.go", want: Tier1Additive},
		{name: "tier1 shim command", path: "cmd/containerd-shim-gvx-v2/main.go", want: Tier1Additive},
		{name: "tier1 shim control", path: "internal/gvxshim/lifecycle.go", want: Tier1Additive},
		{name: "tier1 isolated shim interop", path: "tools/shiminterop/shim_manager_linux_test.go", want: Tier1Additive},
		{name: "tier1 hvf backend", path: "pkg/sentry/platform/hvf/hvf.go", want: Tier1Additive},
		{name: "tier1 hostfs driver", path: "pkg/sentry/fsimpl/hostfs/hostfs.go", want: Tier1Additive},
		{name: "tier1 internal helpers", path: "internal/testelf/elf.go", want: Tier1Additive},
		{name: "tier2 windows futex", path: "pkg/sync/futex_windows.go", want: Tier2Sibling},
		{name: "tier2 darwin memutil", path: "pkg/memutil/memutil_darwin.go", want: Tier2Sibling},
		{name: "tier2 xplat systrap", path: "pkg/sentry/platform/systrap/systrap_xplat.go", want: Tier2Sibling},
		{name: "tier2 arch suffix after os", path: "pkg/sentry/platform/systrap/commit_mm_darwin_arm64.go", want: Tier2Sibling},
		{name: "tier2 assembly trampoline", path: "pkg/sentry/platform/systrap/trampoline_windows_amd64.s", want: Tier2Sibling},
		{name: "tier2 arch before marker", path: "pkg/sentry/platform/systrap/patcher_amd64_xplat.go", want: Tier2Sibling},
		{name: "tier2 darwin test", path: "pkg/sync/futex_darwin_test.go", want: Tier2Sibling},
		{name: "tier3 sentry kernel", path: "pkg/sentry/kernel/kernel.go", want: Tier3Upstream},
		{name: "tier2 linux xplat futex", path: "pkg/sync/futex_linux_xplat.go", want: Tier2Sibling},
		{name: "tier3 token inside word", path: "pkg/sentry/kernel/darwinish.go", want: Tier3Upstream},
		{name: "tier1 ext4lite volume engine", path: "pkg/sentry/fsimpl/ext4lite/ext4lite.go", want: Tier1Additive},
		{name: "tier1 hvcommon shared stubs", path: "pkg/sentry/platform/hvcommon/arm64.go", want: Tier1Additive},
		{name: "tier2 xplat helper in a shared package", path: "pkg/syserr/linux_errno_xplat.go", want: Tier2Sibling},
		{name: "tier2 darwin page size file", path: "pkg/hostarch/hostarch_darwin_arm64_16k.go", want: Tier2Sibling},
		{name: "tier3 helper without a marker", path: "pkg/syserr/linux_errno.go", want: Tier3Upstream},
		{name: "tier1 scripts tree", path: "scripts/linux16k/init.go", want: Tier1Additive},
		{name: "tier1 sentry blockdev", path: "pkg/sentry/blockdev/registry_xplat.go", want: Tier1Additive},
		{name: "tier1 gostateify tool", path: "tools/gostateify/main.go", want: Tier1Additive},
		{name: "tier1 wgtun link", path: "pkg/tcpip/link/wgtun/wgtun.go", want: Tier1Additive},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyFile(tc.path); got != tc.want {
				t.Fatalf("ClassifyFile(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestValidateCommitSHA(t *testing.T) {
	t.Parallel()

	if got, err := ValidateCommitSHA("  " + strings.ToUpper(testSHA) + "\n"); err != nil || got != testSHA {
		t.Fatalf("ValidateCommitSHA(upper) = %q, %v; want lowercase %q", got, err, testSHA)
	}
	if _, err := ValidateCommitSHA(""); !errors.Is(err, errEmptyCommitSHA) {
		t.Fatalf("empty SHA err = %v, want %v", err, errEmptyCommitSHA)
	}
	if _, err := ValidateCommitSHA("abc"); !errors.Is(err, errInvalidCommitSHA) {
		t.Fatalf("short SHA err = %v, want %v", err, errInvalidCommitSHA)
	}
	if _, err := ValidateCommitSHA(strings.Repeat("g", 40)); !errors.Is(err, errInvalidCommitSHA) {
		t.Fatalf("non-hex SHA err = %v, want %v", err, errInvalidCommitSHA)
	}
}

func TestFileMaskPrecedenceAndPatterns(t *testing.T) {
	t.Parallel()

	maskText := `
PROTECT README.md
PROTECT pkg/gvx/**
PROTECT *_darwin.go
PROTECT **/*_xplat*
PROTECT pkg/deep/**/*_windows*
EXCLUDE runsc/**
EXCLUDE **/BUILD
INCLUDE pkg/**
`
	mask, err := ParseFileMaskReader(strings.NewReader(maskText))
	if err != nil {
		t.Fatalf("ParseFileMaskReader: %v", err)
	}
	cases := map[string]MaskDecision{
		"README.md":                           MaskProtect,
		"pkg/sync/futex_darwin.go":            MaskProtect,
		"pkg/tcpip/stack/conntrack_xplat.go":  MaskProtect,
		"pkg/deep/nested/sub/file_windows.go": MaskProtect,
		"runsc/main.go":                       MaskExclude,
		"pkg/sentry/kernel/BUILD":             MaskExclude,
		"pkg/sentry/kernel/kernel.go":         MaskInclude,
		"unlisted/file.go":                    MaskExclude,
		"pkg/gvx/sandbox.go":                  MaskProtect,
		"pkg/sentry/kernel/x_darwin.go":       MaskProtect,
	}
	for rel, want := range cases {
		if got := mask.Decide(rel); got != want {
			t.Errorf("Decide(%q) = %v, want %v", rel, got, want)
		}
	}
	if _, err := ParseFileMaskReader(strings.NewReader("BOGUS x\n")); !errors.Is(err, errInvalidMaskRule) {
		t.Fatalf("unknown directive err = %v, want %v", err, errInvalidMaskRule)
	}
}

// TestRepositoryMaskKeepsUpstreamTreesIncluded pins the sync scope: upstream trees stay in the fork so merges stay conflict-free.
func TestRepositoryMaskKeepsUpstreamTreesIncluded(t *testing.T) {
	t.Parallel()

	mask, err := LoadFileMask("file_mask.txt")
	if err != nil {
		t.Fatalf("LoadFileMask: %v", err)
	}
	for _, rel := range []string{
		"runsc/main.go",
		"sandboxexec/sandbox/sandbox.go",
		"shim/main.go",
		"webhook/main.go",
		"pkg/shim/v1/manager.go",
		"pkg/lisafs/lisafs.go",
		"pkg/sentry/fsimpl/gofer/gofer.go",
		"pkg/sentry/kernel/kernel.go",
		"go.mod",
	} {
		if got := mask.Decide(rel); got != MaskInclude {
			t.Errorf("Decide(%q) = %v, want MaskInclude", rel, got)
		}
	}
	for _, rel := range []string{
		"pkg/gvx/sandbox.go",
		"pkg/sentry/platform/platforms/platforms_darwin.go",
		"pkg/sentry/fsimpl/ext4lite/ext4lite.go",
		"pkg/sentry/platform/hvcommon/arm64.go",
		"internal/testelf/elf.go",
		"cmd/containerd-shim-gvx-v2/main.go",
		"internal/gvxshim/lifecycle.go",
		"tools/shiminterop/shim_manager_linux_test.go",
		"tools/shiminterop/go.mod",
		"CHANGELOG.md",
		"SECURITY.md",
		"tools/licenses/main.go",
		"tools/androidprobe/main.go",
		"tools/gostateify/main.go",
		"android/sdk.go",
		"pkg/sentry/blockdev/registry_xplat.go",
		"pkg/tcpip/link/wgtun/wgtun.go",
		"pkg/tcpip/stack/conntrack_xplat.go",
		"pkg/sentry/fsimpl/proc/rpfilter_xplat.go",
		"pkg/tcpip/stdclock_windows.go",
		"pkg/cpuid/hwcap_darwin_arm64.go",
	} {
		if got := mask.Decide(rel); got != MaskProtect {
			t.Errorf("Decide(%q) = %v, want MaskProtect", rel, got)
		}
	}
}

func TestParseLsRemoteOutputPicksGoBranchAndNewestRelease(t *testing.T) {
	t.Parallel()

	raw := strings.Join([]string{
		"aaaa000000000000000000000000000000000001\trefs/heads/go",
		"bbbb000000000000000000000000000000000002\trefs/tags/release-20260101.0",
		"cccc000000000000000000000000000000000003\trefs/tags/release-20260201.0",
		"dddd000000000000000000000000000000000004\trefs/tags/release-20260201.0^{}",
	}, "\n")
	info, err := parseLsRemoteOutput(raw)
	if err != nil {
		t.Fatalf("parseLsRemoteOutput: %v", err)
	}
	if info.GoBranchSHA != "aaaa000000000000000000000000000000000001" || info.ReleaseTag != "release-20260201.0" {
		t.Fatalf("unexpected refs: %+v", info)
	}
	if _, err := parseLsRemoteOutput("\n"); !errors.Is(err, errUpstreamRefNotFound) {
		t.Fatalf("empty output err = %v, want %v", err, errUpstreamRefNotFound)
	}
}

func TestSyncUpstreamOverlayFiltersRewritesAndRetags(t *testing.T) {
	t.Parallel()

	mask, err := ParseFileMaskReader(strings.NewReader(`
PROTECT README.md
PROTECT *_darwin.go
EXCLUDE runsc/**
EXCLUDE **/BUILD
INCLUDE go.mod
INCLUDE go.sum
INCLUDE pkg/**
`))
	if err != nil {
		t.Fatalf("ParseFileMaskReader: %v", err)
	}
	patches, err := ParsePatchSet(strings.NewReader("linux-only pkg/hostsyscall/\n"))
	if err != nil {
		t.Fatalf("ParsePatchSet: %v", err)
	}

	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module z.gfire.dev/gvx\n\ngo 1.27.4\n\nrequire golang.org/x/arch v0.32.0\n\nreplace golang.org/x/sys => ./internal/xsys\n")
	writeTestFile(t, root, "go.sum", "example.com/local v1.0.0 h1:local\n")
	archivePath := writeArchiveFile(t, map[string]string{
		"README.md":                      "# upstream readme\n",
		"runsc/main.go":                  "package main\n",
		"pkg/sync/futex_darwin.go":       "package sync\n",
		"pkg/sentry/kernel/BUILD":        "load()\n",
		"pkg/sentry/kernel/kernel.go":    "package kernel\n\nimport _ \"gvisor.dev/gvisor/pkg/sync\"\n",
		"pkg/hostsyscall/hostsyscall.go": "package hostsyscall\n",
		"go.mod":                         "module gvisor.dev/gvisor\n\ngo 1.27.4\n\nrequire golang.org/x/mod v0.41.0\n",
		"go.sum":                         "example.com/upstream v2.0.0 h1:up\n",
	})

	manifest, err := SyncUpstream(context.Background(), SyncConfig{
		RootDir:   root,
		TargetRef: testSHA,
		Mask:      mask,
		Patches:   patches,
		Source:    ArchiveSource{ArchivePath: archivePath, Offline: true},
	})
	if err != nil {
		t.Fatalf("SyncUpstream: %v", err)
	}
	if manifest.ExtractedFiles != 4 || manifest.ProtectedSkips != 2 || manifest.ExcludedSkips != 2 {
		t.Fatalf("unexpected manifest counts: %+v", manifest)
	}
	if manifest.Strategy != StrategyArchive {
		t.Fatalf("manifest strategy = %q, want %q", manifest.Strategy, StrategyArchive)
	}

	kernel := readTestFile(t, root, "pkg/sentry/kernel/kernel.go")
	if !strings.Contains(kernel, `"z.gfire.dev/gvx/pkg/sync"`) {
		t.Fatalf("kernel.go kept the upstream module path: %s", kernel)
	}
	hostsyscall := readTestFile(t, root, "pkg/hostsyscall/hostsyscall.go")
	if !strings.HasPrefix(hostsyscall, "//go:build linux\n") {
		t.Fatalf("hostsyscall.go was not fenced by retag: %q", hostsyscall)
	}
	if got := strings.TrimSpace(readTestFile(t, root, "UPSTREAM_COMMIT")); got != testSHA {
		t.Fatalf("UPSTREAM_COMMIT = %q, want %q", got, testSHA)
	}
	if err := ValidateManifest(root, testSHA); err != nil {
		t.Fatalf("ValidateManifest after sync: %v", err)
	}
	gomod := readTestFile(t, root, "go.mod")
	for _, want := range []string{"module z.gfire.dev/gvx", "golang.org/x/mod v0.41.0", "golang.org/x/arch v0.32.0", "replace golang.org/x/sys => ./internal/xsys"} {
		if !strings.Contains(gomod, want) {
			t.Errorf("merged go.mod lacks %q:\n%s", want, gomod)
		}
	}
	gosum := readTestFile(t, root, "go.sum")
	if !strings.Contains(gosum, "example.com/local") || !strings.Contains(gosum, "example.com/upstream") {
		t.Errorf("merged go.sum is not a union:\n%s", gosum)
	}
	for _, rel := range []string{"README.md", "runsc/main.go", "pkg/sync/futex_darwin.go", "pkg/sentry/kernel/BUILD"} {
		if _, err := os.Stat(filepath.Join(root, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("masked path %s exists after sync (stat err %v)", rel, err)
		}
	}
}

func TestSyncUpstreamThreeWayMergesSeamsAndRemovesUpstreamDeletions(t *testing.T) {
	t.Parallel()

	const (
		oldSHA = "1111111111111111111111111111111111111111"
		newSHA = "2222222222222222222222222222222222222222"
	)

	mask, err := ParseFileMaskReader(strings.NewReader(`
PROTECT **/*_xplat*
INCLUDE pkg/**
`))
	if err != nil {
		t.Fatalf("ParseFileMaskReader: %v", err)
	}
	patches, err := ParsePatchSet(strings.NewReader(strings.Join([]string{
		"seam pkg/seam/both.go",
		"seam pkg/seam/localonly.go",
		"pkg/expanded/exp.go",
	}, "\n") + "\n"))
	if err != nil {
		t.Fatalf("ParsePatchSet: %v", err)
	}

	oldUpstream := baseUpstream()
	oldUpstream["pkg/seam/both.go"] = "package seam\n\nfunc Top() int {\n\treturn 1\n}\n\nfunc Bottom() int {\n\treturn 10\n}\n"
	oldUpstream["pkg/seam/localonly.go"] = "package seam\n\nfunc Keep() string {\n\treturn \"upstream\"\n}\n"
	oldUpstream["pkg/expanded/exp.go"] = "//go:build linux\n\npackage expanded\n\nfunc V() int { return 1 }\n"
	oldUpstream["pkg/obsolete/gone.go"] = "package obsolete\n"
	delete(oldUpstream, "runsc/main.go")
	delete(oldUpstream, "pkg/shadow/shadow_darwin.go")

	newUpstream := with(oldUpstream,
		"pkg/seam/both.go", "package seam\n\nfunc Top() int {\n\treturn 2\n}\n\nfunc Bottom() int {\n\treturn 10\n}\n",
		"pkg/expanded/exp.go", "//go:build linux && (amd64 || arm64)\n\npackage expanded\n\nfunc V() int { return 2 }\n",
		"pkg/obsolete/gone.go", "\x00",
	)

	cacheDir := t.TempDir()
	writeCachedArchiveSHA(t, cacheDir, oldSHA, oldUpstream)
	writeCachedArchiveSHA(t, cacheDir, newSHA, newUpstream)

	root := t.TempDir()
	for rel, body := range oldUpstream {
		writeTestFile(t, root, rel, body)
	}
	if _, err := RetagFiles(root, patches); err != nil {
		t.Fatalf("initial RetagFiles: %v", err)
	}
	// Apply local Tier 3 seam edits and add a Tier 2 _xplat sibling in a shared package.
	writeTestFile(t, root, "pkg/seam/both.go", "package seam\n\nfunc Top() int {\n\treturn 1\n}\n\nfunc Bottom() int {\n\treturn 99\n}\n")
	writeTestFile(t, root, "pkg/seam/localonly.go", "package seam\n\nfunc Keep() string {\n\treturn \"gvx-seam\"\n}\n")
	writeTestFile(t, root, "pkg/tcpip/stack/conntrack_xplat.go", "package stack\n\nfunc Track() {}\n")
	writeTestFile(t, root, "UPSTREAM_COMMIT", oldSHA+"\n")
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+oldSHA+`"}`+"\n")

	manifest, err := SyncUpstream(context.Background(), SyncConfig{
		RootDir:   root,
		TargetRef: newSHA,
		MaxRatio:  0.10,
		Audit:     true,
		Mask:      mask,
		Patches:   patches,
		Source:    ArchiveSource{CacheDir: cacheDir, Offline: true},
	})
	if err != nil {
		t.Fatalf("SyncUpstream: %v", err)
	}
	if manifest.MergedFiles != 1 || manifest.DeletedFiles != 1 || len(manifest.Conflicts) != 0 {
		t.Fatalf("unexpected merge manifest: %+v", manifest)
	}
	if got := strings.TrimSpace(readTestFile(t, root, "UPSTREAM_COMMIT")); got != newSHA {
		t.Fatalf("UPSTREAM_COMMIT = %q, want %q", got, newSHA)
	}

	both := readTestFile(t, root, "pkg/seam/both.go")
	if !strings.Contains(both, "return 2") || !strings.Contains(both, "return 99") {
		t.Fatalf("3-way merged pkg/seam/both.go lost an edit:\n%s", both)
	}
	localOnly := readTestFile(t, root, "pkg/seam/localonly.go")
	if !strings.Contains(localOnly, `"gvx-seam"`) {
		t.Fatalf("unchanged upstream clobbered local seam:\n%s", localOnly)
	}
	expanded := readTestFile(t, root, "pkg/expanded/exp.go")
	if !strings.HasPrefix(expanded, ExpandedBuildTag+"\n") || !strings.Contains(expanded, "return 2") {
		t.Fatalf("expanded file did not merge and retag cleanly:\n%s", expanded)
	}
	if _, err := os.Stat(filepath.Join(root, "pkg/obsolete/gone.go")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted upstream file still exists: stat err = %v", err)
	}
	if got := readTestFile(t, root, "pkg/tcpip/stack/conntrack_xplat.go"); !strings.Contains(got, "func Track()") {
		t.Fatalf("protected _xplat file modified: %q", got)
	}
}

func TestSyncUpstreamConflictPreservesOldCommit(t *testing.T) {
	t.Parallel()

	const (
		oldSHA = "3333333333333333333333333333333333333333"
		newSHA = "4444444444444444444444444444444444444444"
	)

	mask, err := ParseFileMaskReader(strings.NewReader("INCLUDE pkg/**\n"))
	if err != nil {
		t.Fatalf("ParseFileMaskReader: %v", err)
	}
	patches, err := ParsePatchSet(strings.NewReader("seam pkg/seam/conflict.go\nseam pkg/seam/delmod.go\n"))
	if err != nil {
		t.Fatalf("ParsePatchSet: %v", err)
	}

	oldUpstream := map[string]string{
		"pkg/seam/conflict.go": "package seam\n\nvar Value = 1\n",
		"pkg/seam/delmod.go":   "package seam\n\nvar Deleted = 1\n",
	}
	newUpstream := map[string]string{
		"pkg/seam/conflict.go": "package seam\n\nvar Value = 2\n",
	}

	cacheDir := t.TempDir()
	writeCachedArchiveSHA(t, cacheDir, oldSHA, oldUpstream)
	writeCachedArchiveSHA(t, cacheDir, newSHA, newUpstream)

	root := t.TempDir()
	writeTestFile(t, root, "pkg/seam/conflict.go", "package seam\n\nvar Value = 99\n")
	writeTestFile(t, root, "pkg/seam/delmod.go", "package seam\n\nvar Deleted = 88\n")
	writeTestFile(t, root, "UPSTREAM_COMMIT", oldSHA+"\n")
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+oldSHA+`"}`+"\n")

	manifest, err := SyncUpstream(context.Background(), SyncConfig{
		RootDir:   root,
		TargetRef: newSHA,
		MaxRatio:  0.50,
		Audit:     true,
		Mask:      mask,
		Patches:   patches,
		Source:    ArchiveSource{CacheDir: cacheDir, Offline: true},
	})
	if !errors.Is(err, errMergeConflicts) {
		t.Fatalf("SyncUpstream err = %v, want %v", err, errMergeConflicts)
	}
	wantConflicts := []string{"pkg/seam/conflict.go", "pkg/seam/delmod.go"}
	if !slices.Equal(manifest.Conflicts, wantConflicts) {
		t.Fatalf("manifest.Conflicts = %v, want %v", manifest.Conflicts, wantConflicts)
	}
	for _, rel := range wantConflicts {
		if !strings.Contains(err.Error(), rel) {
			t.Errorf("conflict error lacks %q: %v", rel, err)
		}
	}
	if got := strings.TrimSpace(readTestFile(t, root, "UPSTREAM_COMMIT")); got != oldSHA {
		t.Fatalf("UPSTREAM_COMMIT = %q, want preserved %q", got, oldSHA)
	}
	if err := ValidateManifest(root, oldSHA); err != nil {
		t.Fatalf("sync_manifest.json was clobbered on conflict: %v", err)
	}
	if conflictBody := readTestFile(t, root, "pkg/seam/conflict.go"); !strings.Contains(conflictBody, "<<<<<<< ours") {
		t.Fatalf("conflicted file lacks conflict markers:\n%s", conflictBody)
	}
	if delModBody := readTestFile(t, root, "pkg/seam/delmod.go"); !strings.Contains(delModBody, "Deleted = 88") {
		t.Fatalf("delete/modify conflict erased local edit:\n%s", delModBody)
	}
}

func TestSyncUpstreamAuditFailurePreservesOldCommit(t *testing.T) {
	t.Parallel()

	const (
		oldSHA = "5555555555555555555555555555555555555555"
		newSHA = "6666666666666666666666666666666666666666"
	)

	mask, err := ParseFileMaskReader(strings.NewReader("EXCLUDE runsc/**\nPROTECT pkg/shadow/*_darwin*\nINCLUDE pkg/**\n"))
	if err != nil {
		t.Fatalf("ParseFileMaskReader: %v", err)
	}
	// Register a stale allowlist rule so post-merge RunAudit fails after clean extraction.
	patches, err := ParsePatchSet(strings.NewReader("pkg/nonexistent/stale.go\n"))
	if err != nil {
		t.Fatalf("ParsePatchSet: %v", err)
	}

	oldUpstream := baseUpstream()
	newUpstream := with(oldUpstream, "pkg/fd/fd.go", "package fd\n\nfunc Updated() {}\n")

	cacheDir := t.TempDir()
	writeCachedArchiveSHA(t, cacheDir, oldSHA, oldUpstream)
	writeCachedArchiveSHA(t, cacheDir, newSHA, newUpstream)

	root := t.TempDir()
	for rel, body := range cleanRepo() {
		writeTestFile(t, root, rel, body)
	}
	writeTestFile(t, root, "UPSTREAM_COMMIT", oldSHA+"\n")
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+oldSHA+`"}`+"\n")

	_, err = SyncUpstream(context.Background(), SyncConfig{
		RootDir:   root,
		TargetRef: newSHA,
		MaxRatio:  0.05,
		Audit:     true,
		Mask:      mask,
		Patches:   patches,
		Source:    ArchiveSource{CacheDir: cacheDir, Offline: true},
	})
	if !errors.Is(err, errStaleRule) {
		t.Fatalf("SyncUpstream err = %v, want %v", err, errStaleRule)
	}
	if got := strings.TrimSpace(readTestFile(t, root, "UPSTREAM_COMMIT")); got != oldSHA {
		t.Fatalf("UPSTREAM_COMMIT = %q, want preserved %q after audit failure", got, oldSHA)
	}
	if err := ValidateManifest(root, oldSHA); err != nil {
		t.Fatalf("sync_manifest.json was clobbered after audit failure: %v", err)
	}
}

func writeCachedArchiveSHA(tb testing.TB, cacheDir, sha string, files map[string]string) string {
	tb.Helper()
	p := filepath.Join(cacheDir, sha+".tar.gz")
	if err := os.WriteFile(p, buildTestTarGzSHA(tb, sha, files), 0o644); err != nil {
		tb.Fatalf("write cached archive %s: %v", sha, err)
	}
	return p
}

func TestSyncUpstreamRejectsMalformedTargetRef(t *testing.T) {
	t.Parallel()

	_, err := SyncUpstream(context.Background(), SyncConfig{RootDir: t.TempDir(), TargetRef: "not-a-sha"})
	if !errors.Is(err, errInvalidCommitSHA) {
		t.Fatalf("SyncUpstream err = %v, want %v", err, errInvalidCommitSHA)
	}
}

func TestStripArchiveRootPrefixRejectsTraversal(t *testing.T) {
	t.Parallel()

	if got, err := stripArchiveRootPrefix("gvisor-abc/pkg/a.go"); err != nil || got != "pkg/a.go" {
		t.Fatalf("stripArchiveRootPrefix = %q, %v", got, err)
	}
	if got, err := stripArchiveRootPrefix("gvisor-abc/"); err != nil || got != "" {
		t.Fatalf("root directory entry = %q, %v; want empty", got, err)
	}
	if _, err := stripArchiveRootPrefix("gvisor-abc/../escape.go"); !errors.Is(err, errUnsafeArchivePath) {
		t.Fatalf("traversal err = %v, want %v", err, errUnsafeArchivePath)
	}
}

// buildTestTarGz returns a gzip tar whose entries live under the codeload root directory for testSHA.
func buildTestTarGz(tb testing.TB, files map[string]string) []byte {
	tb.Helper()
	return buildTestTarGzSHA(tb, testSHA, files)
}

func buildTestTarGzSHA(tb testing.TB, sha string, files map[string]string) []byte {
	tb.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	if err := tw.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": sha}}); err != nil {
		tb.Fatalf("WriteHeader(pax): %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "gvisor-" + sha + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		tb.Fatalf("WriteHeader(root): %v", err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		body := files[name]
		hdr := &tar.Header{
			Name:     "gvisor-" + sha + "/" + name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			tb.Fatalf("WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			tb.Fatalf("Write(%s): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatalf("tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		tb.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func writeArchiveFile(tb testing.TB, files map[string]string) string {
	tb.Helper()
	p := filepath.Join(tb.TempDir(), testSHA+".tar.gz")
	if err := os.WriteFile(p, buildTestTarGz(tb, files), 0o644); err != nil {
		tb.Fatalf("write archive: %v", err)
	}
	return p
}

func writeTestFile(tb testing.TB, root, rel, content string) {
	tb.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tb.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		tb.Fatalf("write %s: %v", rel, err)
	}
}

func readTestFile(tb testing.TB, root, rel string) string {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		tb.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}
