package main

import (
	"errors"
	"strings"
	"testing"
)

func mustPatchSet(t *testing.T, text string) *PatchSet {
	t.Helper()
	ps, err := ParsePatchSet(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParsePatchSet: %v", err)
	}
	return ps
}

func TestParsePatchSetAcceptsEveryDirective(t *testing.T) {
	t.Parallel()

	ps := mustPatchSet(t, `
# comment
pkg/a/a.go
expand pkg/a/b.go
expr pkg/a/c.go linux || darwin
linux-only pkg/a/d.go
linux-only pkg/e/
linux-only pkg/f/ amd64
seam pkg/g/g.go
linux-only pkg/h/**
`)
	cases := []struct {
		rel  string
		kind PatchKind
		expr string
	}{
		{"pkg/a/a.go", PatchExpand, ""},
		{"pkg/a/b.go", PatchExpand, ""},
		{"pkg/a/c.go", PatchExpr, "linux || darwin"},
		{"pkg/a/d.go", PatchLinuxOnly, ""},
		{"pkg/e/anything.go", PatchLinuxOnly, ""},
		{"pkg/f/x.s", PatchLinuxOnly, "amd64"},
		{"pkg/g/g.go", PatchSeam, ""},
		{"pkg/h/a.go", PatchLinuxOnly, ""},
		{"pkg/h/sub/deep/b.go", PatchLinuxOnly, ""},
	}
	for _, tc := range cases {
		got, ok := ps.Lookup(tc.rel)
		if !ok || got.Kind != tc.kind || got.Expr != tc.expr {
			t.Errorf("Lookup(%q) = %+v, %v; want kind %v expr %q", tc.rel, got, ok, tc.kind, tc.expr)
		}
	}
	if _, ok := ps.Lookup("pkg/e/sub/deeper.go"); ok {
		t.Error("directory rule must not cover subdirectories")
	}
	if _, ok := ps.Lookup("pkg/unlisted/x.go"); ok {
		t.Error("Lookup matched an unlisted path")
	}
	if got := len(ps.All()); got != 8 {
		t.Errorf("All() returned %d rules, want 8", got)
	}
}

func TestPatchSetTreeRuleYieldsToDirectoryAndFileRules(t *testing.T) {
	t.Parallel()

	ps := mustPatchSet(t, "linux-only pkg/a/**\nlinux-only pkg/a/b/ amd64\nseam pkg/a/b/c.go\n")
	cases := map[string]PatchKind{
		"pkg/a/x.go":     PatchLinuxOnly,
		"pkg/a/b/y.go":   PatchLinuxOnly,
		"pkg/a/b/c.go":   PatchSeam,
		"pkg/a/b/d/z.go": PatchLinuxOnly,
	}
	for rel, want := range cases {
		if got, ok := ps.Lookup(rel); !ok || got.Kind != want {
			t.Errorf("Lookup(%q) = %+v, %v; want kind %v", rel, got, ok, want)
		}
	}
	if got, _ := ps.Lookup("pkg/a/b/y.go"); got.Expr != "amd64" {
		t.Errorf("directory rule must beat the tree rule, got %+v", got)
	}
	if got, _ := ps.Lookup("pkg/a/b/d/z.go"); got.Path != "pkg/a/**" {
		t.Errorf("tree rule path = %q, want pkg/a/**", got.Path)
	}
	if _, err := ParsePatchSet(strings.NewReader("seam pkg/a/**\n")); !errors.Is(err, errInvalidPatchRule) {
		t.Errorf("seam tree rule err = %v, want %v", err, errInvalidPatchRule)
	}
	if _, err := ParsePatchSet(strings.NewReader("linux-only pkg/a/**\nlinux-only pkg/a/**\n")); !errors.Is(err, errDuplicatePatch) {
		t.Errorf("duplicate tree rule err = %v, want %v", err, errDuplicatePatch)
	}
}

func TestParsePatchSetFileRuleBeatsDirectoryRule(t *testing.T) {
	t.Parallel()

	ps := mustPatchSet(t, "linux-only pkg/a/\nseam pkg/a/special.go\n")
	if got, _ := ps.Lookup("pkg/a/special.go"); got.Kind != PatchSeam {
		t.Fatalf("file rule lost to directory rule: %+v", got)
	}
	if got, _ := ps.Lookup("pkg/a/other.go"); got.Kind != PatchLinuxOnly {
		t.Fatalf("directory rule lost: %+v", got)
	}
}

func TestParsePatchSetRejectsBadRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		text string
		want error
	}{
		{"unknown directive", "bogus pkg/a.go\n", errInvalidPatchRule},
		{"expand with two paths", "expand a.go b.go\n", errInvalidPatchRule},
		{"expr without expression", "expr pkg/a.go\n", errInvalidPatchRule},
		{"bad expression", "expr pkg/a.go linux ||\n", errInvalidConstraint},
		{"bad extra expression", "linux-only pkg/a/ &&&\n", errInvalidConstraint},
		{"absolute path", "linux-only /etc/a.go\n", errInvalidPatchRule},
		{"parent path", "linux-only ../a.go\n", errInvalidPatchRule},
		{"directory in expand rule", "expand pkg/a/\n", errInvalidPatchRule},
		{"duplicate", "pkg/a.go\nseam pkg/a.go\n", errDuplicatePatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParsePatchSet(strings.NewReader(tc.text)); !errors.Is(err, tc.want) {
				t.Fatalf("ParsePatchSet err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestApplyPatchLinuxOnly(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		file     string
		src      string
		extra    string
		want     string
		wantEdit bool
	}{
		{
			name: "unconstrained file gains linux", file: "pkg/x/a.go",
			src: "// Copyright\n\npackage x\n", want: "//go:build linux\n\n// Copyright\n\npackage x\n", wantEdit: true,
		},
		{
			name: "existing constraint is and-ed", file: "pkg/x/a.go",
			src: "//go:build amd64 || arm64\n\npackage x\n", want: "//go:build linux && (amd64 || arm64)\n\npackage x\n", wantEdit: true,
		},
		{
			name: "legacy plus-build line is dropped with the edit", file: "pkg/x/a.go",
			src: "//go:build amd64\n// +build amd64\n\npackage x\n", want: "//go:build linux && amd64\n\npackage x\n", wantEdit: true,
		},
		{
			name: "extra conjunct", file: "pkg/x/a.go", extra: "amd64",
			src: "package x\n", want: "//go:build linux && amd64\n\npackage x\n", wantEdit: true,
		},
		{
			name: "extra conjunct equal to existing constraint is not repeated", file: "pkg/x/a.go", extra: "amd64",
			src: "//go:build amd64\n\npackage x\n", want: "//go:build linux && amd64\n\npackage x\n", wantEdit: true,
		},
		{
			name: "tag that already excludes non-linux stays", file: "pkg/x/a.go",
			src: "//go:build linux\n// +build linux\n\npackage x\n", want: "//go:build linux\n// +build linux\n\npackage x\n",
		},
		{
			name: "linux file name stays untouched", file: "pkg/x/a_linux.go",
			src: "package x\n", want: "package x\n",
		},
		{
			name: "assembly file", file: "pkg/x/a_amd64.s",
			src: "// asm\n", want: "//go:build linux\n\n// asm\n", wantEdit: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, changed, err := applyPatch(tc.file, []byte(tc.src), Patch{Kind: PatchLinuxOnly, Expr: tc.extra})
			if err != nil {
				t.Fatalf("applyPatch: %v", err)
			}
			if changed != tc.wantEdit || string(got) != tc.want {
				t.Fatalf("applyPatch = %q, changed=%v; want %q, changed=%v", got, changed, tc.want, tc.wantEdit)
			}
			again, changedAgain, err := applyPatch(tc.file, got, Patch{Kind: PatchLinuxOnly, Expr: tc.extra})
			if err != nil || changedAgain || string(again) != string(got) {
				t.Fatalf("applyPatch is not idempotent: %q, changed=%v, err=%v", again, changedAgain, err)
			}
		})
	}
}

func TestApplyPatchFencedFileBuildsOnLinuxOnly(t *testing.T) {
	t.Parallel()

	patched, _, err := applyPatch("pkg/x/a.go", []byte("package x\n"), Patch{Kind: PatchLinuxOnly})
	if err != nil {
		t.Fatalf("applyPatch: %v", err)
	}
	nonLinux, err := buildSet("a.go", patched, nonLinuxTargets)
	if err != nil {
		t.Fatalf("buildSet non-linux: %v", err)
	}
	linux, err := buildSet("a.go", patched, linuxTargets)
	if err != nil {
		t.Fatalf("buildSet linux: %v", err)
	}
	if anyTrue(nonLinux) || !allTrue(linux) {
		t.Fatalf("fenced file builds: non-linux=%v linux=%v", nonLinux, linux)
	}
}

func TestApplyPatchExpandAndExpr(t *testing.T) {
	t.Parallel()

	// A file without constraints already builds everywhere: expand must not edit it.
	if got, changed, err := applyPatch("pkg/x/a.go", []byte("package x\n"), Patch{Kind: PatchExpand}); err != nil || changed || string(got) != "package x\n" {
		t.Fatalf("expand on unconstrained file = %q, %v, %v; want no edit", got, changed, err)
	}
	// A Linux-only file is widened to all three operating systems.
	got, changed, err := applyPatch("pkg/x/a.go", []byte("//go:build linux\n// +build linux\n\npackage x\n"), Patch{Kind: PatchExpand})
	if err != nil || !changed || string(got) != "//go:build linux || windows || darwin\n\npackage x\n" {
		t.Fatalf("expand on linux-only file = %q, %v, %v", got, changed, err)
	}
	set, err := buildSet("a.go", got, nonLinuxTargets)
	if err != nil || !allTrue(set) {
		t.Fatalf("expanded file does not build everywhere: %v, %v", set, err)
	}
	// An explicit expression replaces whatever is there and is idempotent.
	got, changed, err = applyPatch("pkg/x/a.go", []byte("package x\n"), Patch{Kind: PatchExpr, Expr: "linux || darwin"})
	if err != nil || !changed || string(got) != "//go:build linux || darwin\n\npackage x\n" {
		t.Fatalf("expr patch = %q, %v, %v", got, changed, err)
	}
	if _, changed, err := applyPatch("pkg/x/a.go", got, Patch{Kind: PatchExpr, Expr: "linux || darwin"}); err != nil || changed {
		t.Fatalf("expr patch is not idempotent: changed=%v err=%v", changed, err)
	}
}

func TestRetagFilesRewritesModuleFencesAndFormatsGeneratedFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	ps := mustPatchSet(t, "linux-only pkg/hostsyscall/\nexpr pkg/memutil/mmap.go linux || darwin\n")
	writeTestFile(t, root, "pkg/hostsyscall/a.go", "package hostsyscall\n\nimport _ \"gvisor.dev/gvisor/pkg/log\"\n")
	writeTestFile(t, root, "pkg/hostsyscall/a_test.go", "package hostsyscall\n")
	writeTestFile(t, root, "pkg/hostsyscall/a_darwin.go", "package hostsyscall\n")
	writeTestFile(t, root, "pkg/memutil/mmap.go", "package memutil\n")
	writeTestFile(t, root, "pkg/log/log_state_autogen.go", "package log\nfunc  f( ) {\n}\n")
	writeTestFile(t, root, "pkg/log/handwritten.go", "package log\nfunc  g( ) {\n}\n")
	writeTestFile(t, root, "tools/upstream/consts.go", "package main\n\nconst x = \"gvisor.dev/gvisor\"\n")

	report, err := RetagFiles(root, ps)
	if err != nil {
		t.Fatalf("RetagFiles: %v", err)
	}
	if report.ModulePath != 1 || report.Patched != 2 || report.Formatted != 1 {
		t.Fatalf("report = %+v, want module=1 patched=2 formatted=1", report)
	}
	if got := readTestFile(t, root, "pkg/hostsyscall/a.go"); !strings.HasPrefix(got, "//go:build linux\n") || !strings.Contains(got, `"z.gfire.dev/gvx/pkg/log"`) {
		t.Errorf("a.go = %q", got)
	}
	if got := readTestFile(t, root, "pkg/hostsyscall/a_test.go"); strings.Contains(got, "go:build") {
		t.Errorf("test file was fenced: %q", got)
	}
	if got := readTestFile(t, root, "pkg/hostsyscall/a_darwin.go"); strings.Contains(got, "go:build") {
		t.Errorf("Tier 2 file was fenced: %q", got)
	}
	if got := readTestFile(t, root, "pkg/memutil/mmap.go"); !strings.HasPrefix(got, "//go:build linux || darwin\n") {
		t.Errorf("mmap.go = %q", got)
	}
	if got := readTestFile(t, root, "pkg/log/log_state_autogen.go"); got != "package log\n\nfunc f() {\n}\n" {
		t.Errorf("generated file was not formatted: %q", got)
	}
	if got := readTestFile(t, root, "pkg/log/handwritten.go"); got != "package log\nfunc  g( ) {\n}\n" {
		t.Errorf("hand-written file was reformatted: %q", got)
	}
	if got := readTestFile(t, root, "tools/upstream/consts.go"); !strings.Contains(got, `"gvisor.dev/gvisor"`) {
		t.Errorf("Tier 1 file was rewritten: %q", got)
	}

	again, err := RetagFiles(root, ps)
	if err != nil {
		t.Fatalf("second RetagFiles: %v", err)
	}
	if again != (RetagReport{}) {
		t.Fatalf("RetagFiles is not idempotent: %+v", again)
	}
}

func TestFilenameGOOS(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"a_linux.go":               "linux",
		"a_linux_amd64.go":         "linux",
		"a_linux_test.go":          "linux",
		"a_amd64.go":               "",
		"a_windows_arm64.s":        "windows",
		"linux.go":                 "",
		"a_linux_unsafe.go":        "",
		"a_darwin.go":              "darwin",
		"state_autogen.go":         "",
		"x_linux_state_autogen.go": "",
	}
	for name, want := range cases {
		if got := filenameGOOS(name); got != want {
			t.Errorf("filenameGOOS(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestBuildSetEvaluatesSanitizerTagSets(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		tag  string
	}{
		{"race", "//go:build race\n\npackage x\n", "race"},
		{"msan", "//go:build msan\n// +build msan\n\npackage x\n", "msan"},
		{"asan", "//go:build asan && amd64\n\npackage x\n", "asan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plain, err := buildSetPlain("a.go", []byte(tc.src), nonLinuxTargets)
			if err != nil || anyTrue(plain) {
				t.Fatalf("plain build set = %v, %v; want no target to compile the file", plain, err)
			}
			tagged, err := buildSet("a.go", []byte(tc.src), nonLinuxTargets)
			if err != nil || !anyTrue(tagged) {
				t.Fatalf("tagged build set = %v, %v; want some case to compile the file", tagged, err)
			}
			for i, c := range buildCases(nonLinuxTargets) {
				if tagged[i] && (len(c.tags) != 1 || c.tags[0] != tc.tag) {
					t.Errorf("file compiles in %s, want only -tags %s", c, tc.tag)
				}
			}

			patched, changed, err := applyPatch("pkg/x/a.go", []byte(tc.src), Patch{Kind: PatchLinuxOnly})
			if err != nil || !changed {
				t.Fatalf("applyPatch = %q, %v, %v; want a fence", patched, changed, err)
			}
			if !strings.Contains(string(patched), "//go:build linux && "+tc.tag) {
				t.Errorf("fenced file = %q, want a linux && %s constraint", patched, tc.tag)
			}
			if strings.Contains(string(patched), "+build") {
				t.Errorf("fenced file kept a stale // +build line: %q", patched)
			}
			after, err := buildSet("a.go", patched, nonLinuxTargets)
			if err != nil || anyTrue(after) {
				t.Fatalf("fenced file still compiles on a non-Linux case: %v, %v", after, err)
			}
			linux, err := buildSet("a.go", patched, linuxTargets)
			if err != nil || !anyTrue(linux) {
				t.Fatalf("fenced file no longer compiles on Linux: %v, %v", linux, err)
			}
			if _, again, err := applyPatch("pkg/x/a.go", patched, Patch{Kind: PatchLinuxOnly}); err != nil || again {
				t.Fatalf("fence is not idempotent: changed=%v err=%v", again, err)
			}
		})
	}
}

func TestExpandRuleIgnoresSanitizerTags(t *testing.T) {
	t.Parallel()

	// An unconstrained file compiles everywhere with every tag set; expand must leave it alone.
	if _, changed, err := applyPatch("pkg/x/a.go", []byte("package x\n"), Patch{Kind: PatchExpand}); err != nil || changed {
		t.Fatalf("expand on unconstrained file: changed=%v err=%v", changed, err)
	}
}

func TestAuditFlagsSanitizerFileThatEscapesTheFence(t *testing.T) {
	t.Parallel()

	up := with(baseUpstream(), "pkg/hostsyscall/race.go", "//go:build race\n\npackage hostsyscall\n")
	unfenced := with(cleanRepo(), "pkg/hostsyscall/race.go", "//go:build race\n\npackage hostsyscall\n")
	fenced := with(cleanRepo(), "pkg/hostsyscall/race.go", "//go:build linux && race\n\npackage hostsyscall\n")
	patches := "linux-only pkg/hostsyscall/\n"

	if _, err := (auditFixture{upstream: up, repo: with(unfenced, "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n"), patches: patches}).run(t); !errors.Is(err, errPatchMismatch) {
		t.Fatalf("unfenced race file: err = %v, want %v", err, errPatchMismatch)
	}
	report, err := auditFixture{upstream: up, repo: with(fenced, "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n"), patches: patches}.run(t)
	if err != nil {
		t.Fatalf("fenced race file failed the audit: %v", err)
	}
	if report.Fence != 2 || report.Budgeted != 0 {
		t.Fatalf("report = %+v, want two fences outside the budget", report)
	}
}

func TestBuildSetEvaluatesCgo(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
	}{
		{"cgo", "//go:build cgo\n// +build cgo\n\npackage x\n"},
		{"pacdisable", "//go:build !false && cgo && arm64\n// +build !false,cgo,arm64\n\npackage x\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plain, err := buildSetPlain("a.go", []byte(tc.src), nonLinuxTargets)
			if err != nil || anyTrue(plain) {
				t.Fatalf("plain build set = %v, %v; want no target to compile without cgo", plain, err)
			}
			tagged, err := buildSet("a.go", []byte(tc.src), nonLinuxTargets)
			if err != nil || !anyTrue(tagged) {
				t.Fatalf("tagged build set = %v, %v; want cgo cases to compile", tagged, err)
			}
			for i, c := range buildCases(nonLinuxTargets) {
				if tagged[i] && !c.cgo {
					t.Errorf("file compiles in %s without cgo", c)
				}
			}

			patched, changed, err := applyPatch("pkg/x/a.go", []byte(tc.src), Patch{Kind: PatchLinuxOnly})
			if err != nil || !changed {
				t.Fatalf("applyPatch = %q, %v, %v; want a fence", patched, changed, err)
			}
			if !strings.Contains(string(patched), "//go:build linux && ") || !strings.Contains(string(patched), "cgo") {
				t.Errorf("fenced file = %q, want a linux && ... cgo constraint", patched)
			}
			if strings.Contains(string(patched), "+build") {
				t.Errorf("fenced file kept a stale // +build line: %q", patched)
			}
			after, err := buildSet("a.go", patched, nonLinuxTargets)
			if err != nil || anyTrue(after) {
				t.Fatalf("fenced file still compiles on a non-Linux case: %v, %v", after, err)
			}
			linux, err := buildSet("a.go", patched, linuxTargets)
			if err != nil || !anyTrue(linux) {
				t.Fatalf("fenced file no longer compiles on Linux: %v, %v", linux, err)
			}
			if _, again, err := applyPatch("pkg/x/a.go", patched, Patch{Kind: PatchLinuxOnly}); err != nil || again {
				t.Fatalf("fence is not idempotent: changed=%v err=%v", again, err)
			}
		})
	}
}

func TestAuditFlagsCgoFileThatEscapesTheFence(t *testing.T) {
	t.Parallel()

	up := with(baseUpstream(), "pkg/hostsyscall/cgo.go", "//go:build cgo\n\npackage hostsyscall\n")
	unfenced := with(cleanRepo(), "pkg/hostsyscall/cgo.go", "//go:build cgo\n\npackage hostsyscall\n")
	fenced := with(cleanRepo(), "pkg/hostsyscall/cgo.go", "//go:build linux && cgo\n\npackage hostsyscall\n")
	patches := "linux-only pkg/hostsyscall/\n"

	if _, err := (auditFixture{upstream: up, repo: with(unfenced, "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n"), patches: patches}).run(t); !errors.Is(err, errPatchMismatch) {
		t.Fatalf("unfenced cgo file: err = %v, want %v", err, errPatchMismatch)
	}
	report, err := auditFixture{upstream: up, repo: with(fenced, "pkg/hostsyscall/sys.go", "//go:build linux\n\npackage hostsyscall\n"), patches: patches}.run(t)
	if err != nil {
		t.Fatalf("fenced cgo file failed the audit: %v", err)
	}
	if report.Fence != 2 || report.Budgeted != 0 {
		t.Fatalf("report = %+v, want two fences outside the budget", report)
	}
}
