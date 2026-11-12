package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const auditMaskText = `
PROTECT pkg/rawfile/*_darwin*
EXCLUDE runsc/**
EXCLUDE **/BUILD
INCLUDE pkg/**
INCLUDE runsc/**
`

// auditFixture describes one synthetic upstream archive and one repository state.
type auditFixture struct {
	upstream map[string]string
	repo     map[string]string
	patches  string
	mask     string
	ratio    float64
	fences   bool
}

// baseUpstream returns an upstream with filler files so that the 5% ceiling stays meaningful.
func baseUpstream() map[string]string {
	files := map[string]string{
		"pkg/kernel/kernel.go":             "package kernel\n",
		"pkg/hostsyscall/sys.go":           "package hostsyscall\n",
		"pkg/memutil/mmap.go":              "package memutil\n",
		"pkg/memutil/mmap_linux.go":        "package memutil\n",
		"pkg/rawfile/shadow_darwin.go":     "package rawfile\n",
		"pkg/erofs/erofs.go":               "package erofs\n\nfunc F() {}\n",
		"pkg/erofs/erofs_state_autogen.go": "package erofs\n\nfunc g() {\n}\n",
		"runsc/main.go":                    "package main\n",
		"pkg/fd/fd.go":                     "package fd\n",
	}
	for i := range 40 {
		files[fmt.Sprintf("pkg/filler/f%02d.go", i)] = "package filler\n"
	}
	return files
}

func (f auditFixture) run(t *testing.T) (AuditReport, error) {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "UPSTREAM_COMMIT", testSHA+"\n")
	for rel, body := range f.repo {
		writeTestFile(t, root, rel, body)
	}
	tree, err := ReadUpstreamArchive(strings.NewReader(string(buildTestTarGz(t, f.upstream))), testSHA)
	if err != nil {
		t.Fatalf("ReadUpstreamArchive: %v", err)
	}
	mask := f.mask
	if mask == "" {
		mask = auditMaskText
	}
	m, err := ParseFileMaskReader(strings.NewReader(mask))
	if err != nil {
		t.Fatalf("ParseFileMaskReader: %v", err)
	}
	ratio := f.ratio
	if ratio == 0 {
		ratio = 0.5
	}
	return RunAudit(AuditConfig{
		RootDir:     root,
		Patches:     mustPatchSet(t, f.patches),
		Mask:        m,
		Upstream:    tree,
		MaxRatio:    ratio,
		CountFences: f.fences,
	})
}

// cleanRepo mirrors baseUpstream with the module path rewritten and runsc removed (it is masked).
func cleanRepo() map[string]string {
	repo := baseUpstream()
	delete(repo, "runsc/main.go")
	return repo
}

func with(files map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(files)+len(kv)/2)
	for k, v := range files {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "\x00" {
			delete(out, kv[i])
			continue
		}
		out[kv[i]] = kv[i+1]
	}
	return out
}

func TestAuditCleanTreeDerivesBaselineFromArchive(t *testing.T) {
	t.Parallel()

	report, err := auditFixture{upstream: baseUpstream(), repo: cleanRepo()}.run(t)
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	// 9 base files + 40 fillers, minus runsc/main.go (mask EXCLUDE).
	if report.UpstreamBaseline != 48 || report.MaskExcluded != 1 {
		t.Fatalf("baseline=%d excluded=%d, want 48 and 1", report.UpstreamBaseline, report.MaskExcluded)
	}
	if report.Pristine != 48 || report.Budgeted != 0 || report.Tier3Count != 47 || report.Tier2Count != 1 || report.Tier2Shadows != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestAuditLinuxFenceIsReproducibleAndOutsideBudget(t *testing.T) {
	t.Parallel()

	repo := with(cleanRepo(), "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n")
	f := auditFixture{upstream: baseUpstream(), repo: repo, patches: "linux-only pkg/hostsyscall/\n", ratio: 0.01}

	report, err := f.run(t)
	if err != nil {
		t.Fatalf("RunAudit: %v", err)
	}
	if report.Fence != 1 || report.Budgeted != 0 || report.StrictRatio <= 0 {
		t.Fatalf("report = %+v, want one fence outside the budget and a positive strict ratio", report)
	}

	f.fences = true
	if _, err := f.run(t); !errors.Is(err, errDiffBudgetExceeded) {
		t.Fatalf("strict audit err = %v, want %v", err, errDiffBudgetExceeded)
	}
}

func TestAuditViolations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		fixture auditFixture
		want    error
	}{
		{
			name: "unlisted build tag edit",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/kernel/kernel.go", "//go:build linux\n\npackage kernel\n")},
			want: errUnlistedBuildTag,
		},
		{
			name: "content edit without a seam",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/kernel/kernel.go", "package kernel\n\nvar Extra = 1\n")},
			want: errUnauthorizedEdit,
		},
		{
			name: "linux-named file with a constraint edit",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/memutil/mmap_linux.go", "//go:build linux && amd64\n\npackage memutil\n")},
			want: errLinuxFileModified,
		},
		{
			name: "linux-named file with a content edit",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/memutil/mmap_linux.go", "package memutil\n\nvar X = 1\n")},
			want: errLinuxFileModified,
		},
		{
			name: "upstream file removed without a mask EXCLUDE",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/fd/fd.go", "\x00")},
			want: errUnmaskedRemoval,
		},
		{
			name: "stale linux-only rule",
			fixture: auditFixture{upstream: baseUpstream(), repo: cleanRepo(),
				patches: "linux-only pkg/hostsyscall/\n"},
			want: errStaleRule,
		},
		{
			name: "rule names a file that does not exist",
			fixture: auditFixture{upstream: baseUpstream(), repo: cleanRepo(),
				patches: "pkg/kernel/missing.go\n"},
			want: errStaleRule,
		},
		{
			name: "redundant fence on a file that already builds nowhere else",
			fixture: auditFixture{
				upstream: with(baseUpstream(), "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n"),
				repo:     with(cleanRepo(), "pkg/hostsyscall/sys.go", "//go:build linux && amd64\n\npackage hostsyscall\n"),
				patches:  "linux-only pkg/hostsyscall/\n"},
			want: errRedundantPatch,
		},
		{
			name: "fence leaves a non-linux target building",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:    with(cleanRepo(), "pkg/hostsyscall/sys.go", "//go:build linux || darwin\n\npackage hostsyscall\n"),
				patches: "linux-only pkg/hostsyscall/\n"},
			want: errPatchMismatch,
		},
		{
			name: "fence stops a linux target building",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:    with(cleanRepo(), "pkg/hostsyscall/sys.go", "//go:build linux && amd64\n\npackage hostsyscall\n"),
				patches: "linux-only pkg/hostsyscall/\n"},
			want: errPatchMismatch,
		},
		{
			name: "expr rule disagrees with file",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:    with(cleanRepo(), "pkg/memutil/mmap.go", "//go:build linux\n\npackage memutil\n"),
				patches: "expr pkg/memutil/mmap.go linux || darwin\n"},
			want: errPatchMismatch,
		},
		{
			name: "expand invariant broken",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:    with(cleanRepo(), "pkg/kernel/kernel.go", "//go:build linux\n\npackage kernel\n"),
				patches: "pkg/kernel/kernel.go\n"},
			want: errPatchMismatch,
		},
		{
			name: "hand-written upstream file reformatted",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/erofs/erofs.go", "package erofs\n\nfunc  F( ) {}\n")},
			want: errNonGeneratedFmt,
		},
		{
			name: "tier 2 file shadows upstream without PROTECT",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/rawfile/shadow_darwin.go", "package rawfile\n\nvar X = 1\n"),
				mask: "EXCLUDE runsc/**\nINCLUDE pkg/**\n"},
			want: errUnprotectedShadow,
		},
		{
			name: "budget exceeded by added files",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:  with(cleanRepo(), "pkg/fd/new1.go", "package fd\n", "pkg/fd/new2.go", "package fd\n", "pkg/fd/new3.go", "package fd\n"),
				ratio: 0.05},
			want: errDiffBudgetExceeded,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.fixture.run(t); !errors.Is(err, tc.want) {
				t.Fatalf("RunAudit err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuditAcceptedDeviations(t *testing.T) {
	t.Parallel()

	generatedFormatted := "package erofs\n\nfunc g() {\n}\n"
	generatedRaw := "package erofs\nfunc  g( ) {\n}\n"
	up := with(baseUpstream(), "pkg/erofs/erofs_state_autogen.go", generatedRaw)

	cases := []struct {
		name    string
		fixture auditFixture
		check   func(t *testing.T, r AuditReport)
	}{
		{
			name: "seam registers a content edit and counts against the budget",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:    with(cleanRepo(), "pkg/erofs/erofs.go", "package erofs\n\nfunc F() { println() }\n"),
				patches: "seam pkg/erofs/erofs.go\n"},
			check: func(t *testing.T, r AuditReport) {
				if r.Seam != 1 || r.Budgeted != 1 {
					t.Fatalf("report = %+v", r)
				}
			},
		},
		{
			name: "gofmt of a generated file is format-only",
			fixture: auditFixture{upstream: up,
				repo: with(cleanRepo(), "pkg/erofs/erofs_state_autogen.go", generatedFormatted)},
			check: func(t *testing.T, r AuditReport) {
				if r.Format != 1 || r.Budgeted != 0 {
					t.Fatalf("report = %+v", r)
				}
			},
		},
		{
			name: "removed legacy plus-build line is format-only",
			fixture: auditFixture{
				upstream: with(baseUpstream(), "pkg/fd/fd.go", "//go:build linux\n// +build linux\n\npackage fd\n"),
				repo:     with(cleanRepo(), "pkg/fd/fd.go", "//go:build linux\n\npackage fd\n")},
			check: func(t *testing.T, r AuditReport) {
				if r.Format != 1 {
					t.Fatalf("report = %+v", r)
				}
			},
		},
		{
			name: "expr and expand rules count against the budget",
			fixture: auditFixture{upstream: baseUpstream(),
				repo:    with(cleanRepo(), "pkg/memutil/mmap.go", "//go:build linux || darwin\n\npackage memutil\n"),
				patches: "expr pkg/memutil/mmap.go linux || darwin\npkg/kernel/kernel.go\n"},
			check: func(t *testing.T, r AuditReport) {
				if r.Expand != 1 || r.Budgeted != 1 {
					t.Fatalf("report = %+v", r)
				}
			},
		},
		{
			name: "protected tier 2 shadow edit counts against the budget",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/rawfile/shadow_darwin.go", "package rawfile\n\nvar X = 1\n")},
			check: func(t *testing.T, r AuditReport) {
				if r.Shadow != 1 || r.Budgeted != 1 {
					t.Fatalf("report = %+v", r)
				}
			},
		},
		{
			name: "added gvx file and added test",
			fixture: auditFixture{upstream: baseUpstream(),
				repo: with(cleanRepo(), "pkg/fd/fd_other.go", "package fd\n", "pkg/fd/fd_test.go", "package fd\n")},
			check: func(t *testing.T, r AuditReport) {
				if r.Added != 1 || r.TestsAdded != 1 || len(r.AddedFiles) != 1 || r.AddedFiles[0] != "pkg/fd/fd_other.go" {
					t.Fatalf("report = %+v", r)
				}
			},
		},
		{
			name:    "masked upstream file may stay absent",
			fixture: auditFixture{upstream: baseUpstream(), repo: cleanRepo()},
			check: func(t *testing.T, r AuditReport) {
				if r.MaskExcluded != 1 {
					t.Fatalf("report = %+v", r)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			report, err := tc.fixture.run(t)
			if err != nil {
				t.Fatalf("RunAudit: %v", err)
			}
			tc.check(t, report)
		})
	}
}

func TestAuditReportsEveryViolationAtOnce(t *testing.T) {
	t.Parallel()

	repo := with(cleanRepo(),
		"pkg/kernel/kernel.go", "//go:build linux\n\npackage kernel\n",
		"pkg/fd/fd.go", "package fd\n\nvar X = 1\n",
	)
	_, err := auditFixture{upstream: baseUpstream(), repo: repo}.run(t)
	if !errors.Is(err, errUnlistedBuildTag) || !errors.Is(err, errUnauthorizedEdit) {
		t.Fatalf("RunAudit err = %v, want both %v and %v", err, errUnlistedBuildTag, errUnauthorizedEdit)
	}
	if n := countErrors(err); n != 2 {
		t.Fatalf("countErrors = %d, want 2", n)
	}
}

func TestRunAuditRejectsBadInputs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeTestFile(t, root, "UPSTREAM_COMMIT", testSHA+"\n")
	if _, err := RunAudit(AuditConfig{RootDir: root, Patches: mustPatchSet(t, ""), MaxRatio: 0}); !errors.Is(err, errInvalidMaxRatio) {
		t.Fatalf("zero ratio err = %v, want %v", err, errInvalidMaxRatio)
	}
	if _, err := RunAudit(AuditConfig{RootDir: root, Patches: mustPatchSet(t, ""), MaxRatio: 0.05}); !errors.Is(err, errNoBaseline) {
		t.Fatalf("nil upstream err = %v, want %v", err, errNoBaseline)
	}
	empty := &UpstreamTree{SHA: testSHA, Files: map[string][]byte{"README.md": []byte("x")}}
	if _, err := RunAudit(AuditConfig{RootDir: root, Patches: mustPatchSet(t, ""), Upstream: empty, MaxRatio: 0.05}); !errors.Is(err, errNoBaseline) {
		t.Fatalf("empty baseline err = %v, want %v", err, errNoBaseline)
	}
	if _, err := RunAudit(AuditConfig{RootDir: t.TempDir(), Patches: mustPatchSet(t, ""), MaxRatio: 0.05}); err == nil {
		t.Fatal("missing UPSTREAM_COMMIT must fail")
	}
}

func TestValidateManifest(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := ValidateManifest(root, testSHA); err == nil {
		t.Fatal("missing manifest must fail")
	}
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{"go_branch_sha": "`+testSHA+`"}`)
	if err := ValidateManifest(root, testSHA); err != nil {
		t.Fatalf("matching manifest: %v", err)
	}
	other := strings.Repeat("a", 40)
	if err := ValidateManifest(root, other); !errors.Is(err, errManifestMismatch) {
		t.Fatalf("mismatch err = %v, want %v", err, errManifestMismatch)
	}
	writeTestFile(t, root, "tools/upstream/sync_manifest.json", `{`)
	if err := ValidateManifest(root, testSHA); err == nil {
		t.Fatal("corrupt manifest must fail")
	}
}

func TestRestoreUnrequiredEditsKeepsContentEditsAndRequiredFences(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	up := baseUpstream()
	repo := with(cleanRepo(),
		"pkg/kernel/kernel.go", "//go:build linux\n\npackage kernel\n", // unrequired fence: restored
		"pkg/memutil/mmap_linux.go", "//go:build linux && amd64\n\npackage memutil\n", // linux file: restored
		"pkg/fd/fd.go", "package fd\n\nvar Seam = 1\n", // content edit: untouched
		"pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n", // required fence: untouched
	)
	for rel, body := range repo {
		writeTestFile(t, root, rel, body)
	}
	writeTestFile(t, root, "UPSTREAM_COMMIT", testSHA+"\n")
	tree, err := ReadUpstreamArchive(strings.NewReader(string(buildTestTarGz(t, up))), testSHA)
	if err != nil {
		t.Fatalf("ReadUpstreamArchive: %v", err)
	}
	cfg := AuditConfig{RootDir: root, Patches: mustPatchSet(t, "linux-only pkg/hostsyscall/\n"), Upstream: tree}

	n, err := RestoreUnrequiredEdits(cfg)
	if err != nil {
		t.Fatalf("RestoreUnrequiredEdits: %v", err)
	}
	if n != 2 {
		t.Fatalf("restored %d files, want 2", n)
	}
	if got := readTestFile(t, root, "pkg/kernel/kernel.go"); got != "package kernel\n" {
		t.Errorf("kernel.go = %q", got)
	}
	if got := readTestFile(t, root, "pkg/memutil/mmap_linux.go"); got != "package memutil\n" {
		t.Errorf("mmap_linux.go = %q", got)
	}
	if got := readTestFile(t, root, "pkg/fd/fd.go"); !strings.Contains(got, "Seam") {
		t.Errorf("content edit was discarded: %q", got)
	}
	if got := readTestFile(t, root, "pkg/hostsyscall/sys.go"); !strings.HasPrefix(got, "//go:build linux") {
		t.Errorf("required fence was discarded: %q", got)
	}
}

func TestAuditNonGoSourcesMustMatchUpstream(t *testing.T) {
	t.Parallel()

	upstream := with(baseUpstream(),
		"pkg/rawfile/ring.c", "int ring;\n",
		"pkg/rawfile/ring.h", "extern int ring;\n",
		"pkg/rawfile/vdso.S", "nop\n",
		"pkg/rawfile/ring.proto", "syntax = \"proto3\";\n",
	)
	repo := with(cleanRepo(),
		"pkg/rawfile/ring.c", "int ring;\n",
		"pkg/rawfile/ring.h", "extern int ring;\n",
		"pkg/rawfile/vdso.S", "nop\n",
		"pkg/rawfile/ring.proto", "syntax = \"proto3\";\n",
		"pkg/rawfile/extra.c", "int extra;\n",
	)

	t.Run("pristine and added files pass", func(t *testing.T) {
		t.Parallel()
		report, err := auditFixture{upstream: upstream, repo: repo}.run(t)
		if err != nil {
			t.Fatalf("RunAudit: %v", err)
		}
		if report.NonGoPristine != 4 || report.NonGoAdded != 1 || report.NonGoMissing != 0 {
			t.Fatalf("non-Go counts pristine=%d added=%d missing=%d, want 4, 1, 0", report.NonGoPristine, report.NonGoAdded, report.NonGoMissing)
		}
		if report.Budgeted != 0 {
			t.Errorf("non-Go files changed the Go budget: %d", report.Budgeted)
		}
	})

	for _, rel := range []string{"pkg/rawfile/ring.c", "pkg/rawfile/ring.h", "pkg/rawfile/vdso.S", "pkg/rawfile/ring.proto"} {
		t.Run("edit of "+rel+" fails", func(t *testing.T) {
			t.Parallel()
			_, err := auditFixture{upstream: upstream, repo: with(repo, rel, "tampered\n")}.run(t)
			if !errors.Is(err, errNonGoModified) || !strings.Contains(err.Error(), rel) {
				t.Fatalf("RunAudit = %v, want errNonGoModified naming %s", err, rel)
			}
		})
	}

	t.Run("protected edit passes", func(t *testing.T) {
		t.Parallel()
		report, err := auditFixture{
			upstream: upstream,
			repo:     with(repo, "pkg/rawfile/ring.c", "int mine;\n"),
			mask:     auditMaskText + "PROTECT pkg/rawfile/ring.c\n",
		}.run(t)
		if err != nil {
			t.Fatalf("RunAudit: %v", err)
		}
		if report.NonGoProtected != 1 {
			t.Errorf("NonGoProtected = %d, want 1", report.NonGoProtected)
		}
	})

	t.Run("missing file is counted", func(t *testing.T) {
		t.Parallel()
		report, err := auditFixture{upstream: upstream, repo: with(repo, "pkg/rawfile/ring.h", "\x00")}.run(t)
		if err != nil {
			t.Fatalf("RunAudit: %v", err)
		}
		if report.NonGoMissing != 1 {
			t.Errorf("NonGoMissing = %d, want 1", report.NonGoMissing)
		}
	})
}
