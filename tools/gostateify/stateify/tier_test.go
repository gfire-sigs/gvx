package stateify

import (
	"go/build/constraint"
	"os"
	"path/filepath"
	"testing"
)

func mustParseConstraint(t *testing.T, line string) constraint.Expr {
	t.Helper()
	if line == "" {
		return nil
	}
	expr, err := constraint.Parse("//go:build " + line)
	if err != nil {
		t.Fatalf("constraint.Parse(%q): %v", line, err)
	}
	return expr
}

func TestExtractFileConstraintAndSimplification(t *testing.T) {
	cases := []struct {
		name     string
		baseName string
		src      string
		want     string
	}{
		{
			name:     "unconstrained",
			baseName: "common.go",
			src:      "package foo\n",
			want:     "",
		},
		{
			name:     "implicit_darwin",
			baseName: "mem_darwin.go",
			src:      "package foo\n",
			want:     "darwin",
		},
		{
			name:     "implicit_windows_amd64",
			baseName: "stub_windows_amd64.go",
			src:      "package foo\n",
			want:     "windows && amd64",
		},
		{
			name:     "explicit_and_implicit_dedup",
			baseName: "mem_darwin.go",
			src:      "//go:build darwin\n\npackage foo\n",
			want:     "darwin",
		},
		{
			name:     "xplat_has_no_implicit_os",
			baseName: "helper_xplat.go",
			src:      "//go:build windows || darwin\n\npackage foo\n",
			want:     "windows || darwin",
		},
		{
			name:     "legacy_plus_build_fallback",
			baseName: "legacy.go",
			src:      "// +build linux,amd64\n\npackage foo\n",
			want:     "linux && amd64",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := ExtractFileConstraint(tc.baseName, []byte(tc.src))
			if err != nil {
				t.Fatalf("ExtractFileConstraint(%q): %v", tc.baseName, err)
			}
			got := ""
			if expr != nil {
				got = expr.String()
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConstraintCoverageEquivalenceAndExclusion(t *testing.T) {
	winOrDarwin := mustParseConstraint(t, "windows || darwin")
	darwinOrWin := mustParseConstraint(t, "darwin || windows")
	if !EquivalentConstraints(winOrDarwin, darwinOrWin) {
		t.Fatal("expected windows || darwin and darwin || windows to be equivalent")
	}

	win := mustParseConstraint(t, "windows")
	winAmd64 := mustParseConstraint(t, "windows && amd64")
	winArm64 := mustParseConstraint(t, "windows && arm64")

	if !CoversConstraint(nil, win) {
		t.Fatal("expected unconstrained nil to cover windows")
	}
	if CoversConstraint(win, nil) {
		t.Fatal("expected windows not to cover unconstrained nil")
	}
	if !CoversConstraint(win, winAmd64) {
		t.Fatal("expected windows to cover windows && amd64")
	}
	if CoversConstraint(winAmd64, win) {
		t.Fatal("expected windows && amd64 not to cover windows")
	}
	if !CoversConstraint(winOrDarwin, winAmd64) {
		t.Fatal("expected windows || darwin to cover windows && amd64")
	}
	if !AreMutuallyExclusive(winAmd64, winArm64) {
		t.Fatal("expected windows && amd64 and windows && arm64 to be mutually exclusive")
	}
	if AreMutuallyExclusive(win, winAmd64) {
		t.Fatal("expected windows and windows && amd64 not to be mutually exclusive")
	}
}

func TestSubPartitionOutputFileName(t *testing.T) {
	cases := []struct {
		kind PartitionKind
		expr string
		want string
	}{
		{PartitionDefault, "", "sample_state_autogen.go"},
		{PartitionDefault, "amd64", "sample_amd64_state_autogen.go"},
		{PartitionXplat, "", "sample_xplat_state_autogen.go"},
		{PartitionXplat, "windows || darwin", "sample_xplat_darwin_windows_state_autogen.go"},
		{PartitionWindows, "windows", "sample_windows_state_autogen.go"},
		{PartitionWindows, "windows && amd64", "sample_windows_amd64_state_autogen.go"},
		{PartitionWindows, "windows && arm64", "sample_windows_arm64_state_autogen.go"},
		{PartitionDarwin, "darwin", "sample_darwin_state_autogen.go"},
		{PartitionDarwin, "darwin && arm64", "sample_darwin_arm64_state_autogen.go"},
		{PartitionLinux, "linux", "sample_linux_state_autogen.go"},
	}
	for _, tc := range cases {
		got := SubPartitionOutputFileName("sample", tc.kind, mustParseConstraint(t, tc.expr))
		if got != tc.want {
			t.Fatalf("SubPartitionOutputFileName(%s, %q) = %q, want %q", tc.kind, tc.expr, got, tc.want)
		}
	}
}

func TestClassifyPackageAndPartition(t *testing.T) {
	if len(Tier1Prefixes()) == 0 {
		t.Fatal("expected non-empty Tier1Prefixes")
	}
	if got := ClassifyPackage("pkg/sentry/fsimpl/hostfs"); got != PackageTier1 {
		t.Fatalf("hostfs tier = %v, want PackageTier1", got)
	}
	if got := ClassifyPackage("tools/gostateify"); got != PackageTier1 {
		t.Fatalf("tools/gostateify tier = %v, want PackageTier1", got)
	}
	if got := ClassifyPackage("pkg/sentry/kernel"); got != PackageTierShared {
		t.Fatalf("kernel tier = %v, want PackageTierShared", got)
	}
	if got := ClassifyFilePartition(PackageTierShared, "cpu_xplat.go", true); got != PartitionXplat {
		t.Fatalf("cpu_xplat.go partition = %v, want PartitionXplat", got)
	}
	if got := ClassifyFilePartition(PackageTierShared, "foo_unsafe.go", true); got != PartitionUnsafe {
		t.Fatalf("foo_unsafe.go partition = %v, want PartitionUnsafe", got)
	}
	if got := ClassifyFilePartition(PackageTierShared, "foo_abi_autogen_unsafe.go", true); got != PartitionDefault {
		t.Fatalf("foo_abi_autogen_unsafe.go partition = %v, want PartitionDefault", got)
	}
	if got := ClassifyFilePartition(PackageTier1, "inode_linux.go", true); got != PartitionLinux {
		t.Fatalf("Tier 1 inode_linux.go partition = %v, want PartitionLinux", got)
	}
	if got := classifyFilePartition(PackageTier1, "registry_xplat.go", true, true); got != PartitionDefault {
		t.Fatalf("Tier 1 merged registry_xplat.go partition = %v, want PartitionDefault", got)
	}
}

func TestReadPackagesFileTierOptions(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "packages.txt")
	content := "# registered packages\npkg/sentry/blockdev tier1\npkg/sentry/kernel tier2\npkg/bitmap\n"
	if err := os.WriteFile(validPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := readPackagesFile(validPath)
	if err != nil {
		t.Fatalf("readPackagesFile: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if !entries[0].tier1 || entries[0].tier2Only {
		t.Fatalf("entries[0] = %+v, want tier1=true tier2Only=false", entries[0])
	}
	if entries[1].tier1 || !entries[1].tier2Only {
		t.Fatalf("entries[1] = %+v, want tier1=false tier2Only=true", entries[1])
	}
	if entries[2].tier1 || entries[2].tier2Only {
		t.Fatalf("entries[2] = %+v, want tier1=false tier2Only=false", entries[2])
	}

	conflictPath := filepath.Join(dir, "conflict.txt")
	if err := os.WriteFile(conflictPath, []byte("pkg/sentry/blockdev tier1 tier2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPackagesFile(conflictPath); err == nil {
		t.Fatal("expected error for conflicting tier1 and tier2 options")
	}
}
