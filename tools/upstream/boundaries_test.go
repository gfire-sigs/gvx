package main

import (
	"errors"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func importLines(imports ...string) string {
	var b strings.Builder
	b.WriteString("package p\n\nimport (\n")
	for _, imp := range imports {
		b.WriteString("\t_ \"" + imp + "\"\n")
	}
	b.WriteString(")\n")
	return b.String()
}

// boundaryCheck writes one file and returns the violations that auditFileImports reports.
func boundaryCheck(t *testing.T, rel, body string) []BoundaryViolation {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, rel, body)
	vs, err := auditFileImports(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(rel)), rel, ClassifyFile(rel))
	if err != nil {
		t.Fatalf("auditFileImports(%s): %v", rel, err)
	}
	return vs
}

func TestBoundaryAllowListsFollowSpecTable(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	cases := []struct {
		name    string
		file    string
		imports []string
		bad     []string
	}{
		{
			name: "isolated shim interop imports upstream without the root module", file: "tools/shiminterop/shim_manager_linux_test.go",
			imports: []string{"github.com/containerd/containerd/v2/core/runtime/v2", "github.com/containerd/containerd/api/runtime/task/v3", "github.com/containerd/typeurl/v2", "golang.org/x/sys/unix"},
			bad:     []string{m + "internal/gvxshim", m + "pkg/gvx", m + "pkg/sentry/kernel", m + "runsc/boot", m + "cmd/containerd-shim-gvx-v2"},
		},
		{
			name: "shim command only composes the adapter", file: "cmd/containerd-shim-gvx-v2/main.go",
			imports: []string{m + "internal/gvxshim", "os"},
			bad:     []string{m + "pkg/gvx", m + "pkg/sentry/kernel", m + "runsc/boot", m + "shim/v1/cli"},
		},
		{
			name: "shim control has no guest runtime dependency", file: "internal/gvxshim/service.go",
			imports: []string{"context", "golang.org/x/sys/unix", "golang.org/x/sys/windows", "github.com/Microsoft/go-winio", "github.com/containerd/ttrpc", "github.com/containerd/containerd/api/runtime/task/v3", "github.com/containerd/containerd/v2/pkg/identifiers", "google.golang.org/grpc/status", "google.golang.org/protobuf/proto"},
			bad:     []string{m + "pkg/gvx", m + "pkg/hostlockdown", m + "pkg/sentry/kernel", m + "runsc/boot", m + "cmd/rungv", m + "shim/v1/cli", "github.com/containerd/containerd/v2/pkg/shim", "github.com/containerd/containerd/v2/client"},
		},
		{
			name: "cmd/rungv may import gvx and oci only", file: "cmd/rungv/main.go",
			imports: []string{m + "pkg/gvx", m + "pkg/oci", "flag"},
			bad:     []string{m + "pkg/netbackend", m + "pkg/hostlockdown", m + "pkg/sentry/kernel", m + "pkg/log"},
		},
		{
			name: "pkg/gvx coordinates the subsystems", file: "pkg/gvx/sandbox.go",
			imports: []string{m + "pkg/oci", m + "pkg/netbackend", m + "pkg/hostlockdown", m + "pkg/sentry/vfs", m + "pkg/sentry/kernel", m + "pkg/fd", m + "pkg/tcpip/stack", m + "pkg/context", m + "pkg/cpuid"},
			bad:     []string{m + "cmd/rungv", m + "pkg/rand", m + "pkg/unet", m + "internal/gvxshim"},
		},
		{
			name: "pkg/oci stays independent of the sentry", file: "pkg/oci/pull.go",
			imports: []string{m + "pkg/abi/linux", m + "pkg/erofs", "github.com/klauspost/compress/zstd", "github.com/cespare/xxhash/v2", "archive/tar"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/sentry/vfs", m + "pkg/hostlockdown", m + "pkg/tcpip", m + "pkg/log"},
		},
		{
			name: "pkg/netbackend bridges tcpip", file: "pkg/netbackend/nat.go",
			imports: []string{m + "pkg/tcpip", m + "pkg/tcpip/stack", m + "pkg/tcpip/adapters/gonet", m + "pkg/buffer", m + "pkg/waiter", "golang.zx2c4.com/wireguard/device", "golang.org/x/sys/windows"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/sentry/vfs", m + "pkg/hostlockdown", m + "pkg/log"},
		},
		{
			name: "pkg/hostlockdown touches host APIs only", file: "pkg/hostlockdown/lockdown_darwin.go",
			imports: []string{"golang.org/x/sys/unix", "golang.org/x/sys/windows"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/tcpip", m + "pkg/log", m + "pkg/fd"},
		},
		{
			name: "whpx backend", file: "pkg/sentry/platform/whpx/whpx.go",
			imports: []string{m + "pkg/sentry/platform", m + "pkg/memutil", m + "pkg/abi/linux", "golang.org/x/sys/windows", m + "pkg/context", m + "pkg/hostarch", m + "pkg/sentry/arch", m + "pkg/sentry/memmap"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/sentry/vfs", m + "pkg/sentry/platform/hvf", m + "pkg/sentry/platform/systrap", "golang.org/x/sys/unix", m + "pkg/hostlockdown"},
		},
		{
			name: "hvf backend", file: "pkg/sentry/platform/hvf/hvf.go",
			imports: []string{m + "pkg/sentry/platform", m + "pkg/memutil", m + "pkg/abi/linux", "golang.org/x/sys/unix", m + "pkg/usermem"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/sentry/vfs", m + "pkg/sentry/platform/whpx", m + "pkg/hostlockdown", "golang.org/x/sys/windows"},
		},
		{
			name: "systrap sibling file", file: "pkg/sentry/platform/systrap/systrap_xplat.go",
			imports: []string{m + "pkg/sentry/platform", m + "pkg/memutil", m + "pkg/abi/linux", "golang.org/x/arch/x86/x86asm", "golang.org/x/arch/arm64/arm64asm", "golang.org/x/sys/windows"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/sentry/platform/whpx", m + "pkg/sentry/platform/hvf", m + "pkg/rand"},
		},
		{
			name: "hostfs mounts host files", file: "pkg/sentry/fsimpl/hostfs/hostfs.go",
			imports: []string{m + "pkg/sentry/vfs", m + "pkg/abi/linux", m + "pkg/fd", "golang.org/x/sys/windows", "golang.org/x/sys/unix", m + "pkg/sentry/kernel/auth", m + "pkg/sentry/limits", m + "pkg/sentry/socket/unix/transport"},
			bad:     []string{m + "pkg/sentry/platform", m + "pkg/sentry/platform/hvf", m + "pkg/rand"},
		},
		{
			name: "pkg/sync sibling file", file: "pkg/sync/futex_windows.go",
			imports: []string{"golang.org/x/sys/windows/registry", "sync/atomic"},
			bad:     []string{m + "pkg/sentry/kernel", m + "pkg/gohacks"},
		},
		{
			name: "pkg/memutil sibling file", file: "pkg/memutil/memutil_darwin.go",
			imports: []string{"golang.org/x/sys/unix"},
			bad:     []string{m + "pkg/sentry/usage", m + "pkg/hostarch"},
		},
		{
			name: "pkg/fd sibling file", file: "pkg/fd/fd_windows.go",
			imports: []string{"golang.org/x/sys/windows", "golang.org/x/sys/unix"},
			bad:     []string{m + "pkg/sentry/vfs", m + "pkg/log"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if vs := boundaryCheck(t, tc.file, importLines(tc.imports...)); len(vs) != 0 {
				t.Errorf("allowed imports flagged: %v", vs)
			}
			for _, bad := range tc.bad {
				vs := boundaryCheck(t, tc.file, importLines(bad))
				if len(vs) != 1 {
					t.Errorf("import %s: got %d violations, want 1", bad, len(vs))
					continue
				}
				if !errors.Is(vs[0], errForbiddenImport) {
					t.Errorf("violation does not wrap errForbiddenImport: %v", vs[0])
				}
			}
		})
	}
}

func TestBoundaryForbiddenListCoversUpstreamTierThreeFiles(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	// Kernel is upstream code: only the forbidden column applies.
	if vs := boundaryCheck(t, "pkg/sentry/kernel/task.go", importLines(m+"pkg/tcpip", m+"pkg/sentry/mm", "golang.org/x/sys/unix")); len(vs) != 0 {
		t.Errorf("kernel imports of unlisted packages flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/kernel/task.go", importLines("golang.org/x/sys/windows")); len(vs) != 1 {
		t.Errorf("kernel import of x/sys/windows: %d violations, want 1", len(vs))
	}
	if vs := boundaryCheck(t, "pkg/sentry/kernel/task.go", importLines(m+"pkg/hostlockdown")); len(vs) != 1 {
		t.Errorf("kernel import of hostlockdown: %d violations, want 1", len(vs))
	}
	// pkg/sync is upstream code in Tier 3 but its sibling files are Tier 2.
	if vs := boundaryCheck(t, "pkg/sync/mutex.go", importLines(m+"pkg/gohacks", m+"pkg/goid")); len(vs) != 0 {
		t.Errorf("upstream pkg/sync imports flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sync/mutex.go", importLines(m+"pkg/sentry/usage")); len(vs) != 1 {
		t.Errorf("upstream pkg/sync import of sentry: %d violations, want 1", len(vs))
	}
}

func TestBoundaryIgnoresUpstreamFilesNoWindowsOrMacTargetBuilds(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	// systrap upstream code imports the kernel on Linux; the fence keeps it out of Windows and macOS builds.
	linuxOnly := "//go:build linux\n\n" + importLines(m+"pkg/sentry/kernel")
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/subprocess_amd64.go", linuxOnly); len(vs) != 0 {
		t.Errorf("linux-only upstream file flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/subprocess_linux.go", importLines(m+"pkg/sentry/kernel")); len(vs) != 0 {
		t.Errorf("_linux upstream file flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/subprocess.go", importLines(m+"pkg/sentry/kernel")); len(vs) != 1 {
		t.Errorf("unconstrained upstream file: %d violations, want 1", len(vs))
	}
	// The exemption never covers files that gvx wrote.
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/x_xplat.go", linuxOnly); len(vs) != 1 {
		t.Errorf("tier 2 file with a forbidden import: %d violations, want 1", len(vs))
	}
}

func TestBoundaryUsertrapMayImportTheKernelButNotAHardwareBackend(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	// usertrap is upstream code that reads guest memory through kernel.Task.
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/usertrap/usertrap_amd64.go", importLines(m+"pkg/sentry/kernel")); len(vs) != 0 {
		t.Errorf("usertrap importing the kernel flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/usertrap/usertrap_amd64.go", importLines(m+"pkg/sentry/platform/whpx", m+"pkg/sentry/platform/hvf")); len(vs) != 2 {
		t.Errorf("usertrap importing a hardware backend: %d violations, want 2", len(vs))
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/usertrap/rewrite_xplat_amd64.go", importLines(m+"pkg/context", m+"pkg/hostarch", m+"pkg/safemem")); len(vs) != 0 {
		t.Errorf("usertrap xplat sibling importing foundation packages flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/usertrap/rewrite_xplat_amd64.go", importLines(m+"pkg/sentry/platform/whpx")); len(vs) != 1 {
		t.Errorf("usertrap xplat sibling importing whpx: %d violations, want 1", len(vs))
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/usertrap/rewrite_xplat_amd64.go", importLines(m+"pkg/sentry/kernel")); len(vs) != 1 {
		t.Errorf("usertrap xplat sibling importing kernel: %d violations, want 1", len(vs))
	}
	// The rest of systrap keeps the kernel ban.
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/context_queue.go", importLines(m+"pkg/sentry/kernel")); len(vs) != 1 {
		t.Errorf("systrap importing the kernel: %d violations, want 1", len(vs))
	}
}

func TestBoundaryTestExceptionsApplyToTestFilesOnly(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	fixture := importLines(m+"internal/testelf", m+"internal/testimage")
	if vs := boundaryCheck(t, "pkg/gvx/sandbox_test.go", fixture); len(vs) != 0 {
		t.Errorf("fixture imports in pkg/gvx tests flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "cmd/rungv/main_hw_test.go", fixture); len(vs) != 0 {
		t.Errorf("fixture imports in cmd/rungv tests flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/gvx/sandbox.go", fixture); len(vs) != 2 {
		t.Errorf("fixture imports in pkg/gvx production code: %d violations, want 2", len(vs))
	}
	if vs := boundaryCheck(t, "pkg/oci/overlay_test.go", importLines(m+"internal/testimage")); len(vs) != 1 {
		t.Errorf("pkg/oci tests must not gain the fixture exception: %d violations, want 1", len(vs))
	}
}

func TestBoundaryForbiddenWinsOverException(t *testing.T) {
	t.Parallel()

	// pkg/gvx lists pkg/sentry/* as allowed, but cmd/rungv forbids it even in tests.
	vs := boundaryCheck(t, "cmd/rungv/main_test.go", importLines(modulePrefix+"pkg/sentry/vfs"))
	if len(vs) != 1 || !strings.Contains(vs[0].Reason, "forbidden") {
		t.Fatalf("violations = %v, want one forbidden-list violation", vs)
	}
}

func TestBoundaryHvcommonIsSharedByBothHardwareBackends(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	for _, file := range []string{"pkg/sentry/platform/whpx/x.go", "pkg/sentry/platform/hvf/x.go", "pkg/sentry/platform/systrap/x_xplat.go"} {
		if vs := boundaryCheck(t, file, importLines(m+"pkg/sentry/platform/hvcommon")); len(vs) != 0 {
			t.Errorf("%s importing hvcommon flagged: %v", file, vs)
		}
	}
	if vs := boundaryCheck(t, "pkg/sentry/fsimpl/hostfs/x.go", importLines(m+"pkg/sentry/platform/hvcommon")); len(vs) != 1 {
		t.Errorf("hostfs importing hvcommon: %d violations, want 1", len(vs))
	}
	// hvcommon holds pure helpers. It never imports a backend.
	for _, backend := range []string{"whpx", "hvf", "systrap"} {
		if vs := boundaryCheck(t, "pkg/sentry/platform/hvcommon/x.go", importLines(m+"pkg/sentry/platform/"+backend)); len(vs) != 1 {
			t.Errorf("hvcommon importing %s: %d violations, want 1", backend, len(vs))
		}
	}
}

func TestBoundaryExt4liteNeverImportsAPlatformBackend(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	if vs := boundaryCheck(t, "pkg/sentry/fsimpl/ext4lite/x.go", importLines(m+"pkg/sentry/vfs", m+"pkg/abi/linux", m+"pkg/fd")); len(vs) != 0 {
		t.Errorf("ext4lite VFS imports flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/fsimpl/ext4lite/x.go", importLines(m+"pkg/sentry/platform/whpx")); len(vs) != 1 {
		t.Errorf("ext4lite importing a platform backend: %d violations, want 1", len(vs))
	}
}

func TestBoundaryAllowsOwnSubtreeAndStdlib(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	if vs := boundaryCheck(t, "pkg/netbackend/sub/x.go", importLines(m+"pkg/netbackend", m+"pkg/netbackend/other", "net/http", "unsafe", "C")); len(vs) != 0 {
		t.Errorf("own subtree or stdlib flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/other/x.go", importLines(m+"pkg/sentry/kernel")); len(vs) != 0 {
		t.Errorf("package without a rule flagged: %v", vs)
	}
}

func TestBoundaryLegacyModulePathIsNormalized(t *testing.T) {
	t.Parallel()

	if vs := boundaryCheck(t, "pkg/oci/pull.go", importLines("gvisor.dev/gvisor/pkg/sentry/kernel")); len(vs) != 1 {
		t.Fatalf("legacy module path import: %d violations, want 1", len(vs))
	}
}

func TestBoundaryRejectsWinHvPlatformLiteral(t *testing.T) {
	t.Parallel()

	body := "package p\n\nvar dll = \"winhvplatform.DLL\"\n"
	for _, file := range []string{"cmd/rungv/main.go", "pkg/netbackend/nat.go"} {
		if vs := boundaryCheck(t, file, body); len(vs) != 1 || !strings.Contains(vs[0].Reason, "literal") {
			t.Errorf("%s: violations = %v, want one literal violation", file, vs)
		}
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/whpx/whpx_windows.go", body); len(vs) != 0 {
		t.Errorf("whpx may name its own DLL: %v", vs)
	}
}

func TestBoundaryExceptionsNameTheirReason(t *testing.T) {
	t.Parallel()

	for _, list := range [][]importException{boundaryExceptions, boundaryTestExceptions} {
		for _, ex := range list {
			if len(ex.pkgs) == 0 || ex.prefix == "" || len(strings.Fields(ex.reason)) < 3 {
				t.Errorf("exception %+v lacks a package, prefix, or reason", ex)
			}
			for _, p := range ex.pkgs {
				known := false
				for _, rule := range boundaryRules {
					known = known || rule.pkg == p
				}
				if !known {
					t.Errorf("exception for %q matches no boundary rule", p)
				}
			}
		}
	}
}

func TestMatchImportPattern(t *testing.T) {
	t.Parallel()

	cases := []struct {
		pattern, imp string
		want         bool
	}{
		{"pkg/sentry/*", "pkg/sentry", true},
		{"pkg/sentry/*", "pkg/sentry/kernel/auth", true},
		{"pkg/sentry/*", "pkg/sentryx", false},
		{"pkg/fd", "pkg/fd", true},
		{"pkg/fd", "pkg/fd/sub", false},
		{"golang.org/x/arch/*", "golang.org/x/arch/x86/x86asm", true},
	}
	for _, tc := range cases {
		if got := matchImportPattern(tc.pattern, tc.imp); got != tc.want {
			t.Errorf("matchImportPattern(%q, %q) = %v, want %v", tc.pattern, tc.imp, got, tc.want)
		}
	}
}

func TestBoundaryPlatformSharedLibraries(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	for _, file := range []string{"pkg/sentry/platform/whpx/context.go", "pkg/sentry/platform/hvf/context.go"} {
		if vs := boundaryCheck(t, file, importLines(m+"pkg/sentry/platform/interrupt", m+"pkg/ring0/pagetables")); len(vs) != 0 {
			t.Errorf("%s: shared platform libraries flagged: %v", file, vs)
		}
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/x_xplat.go", importLines(m+"pkg/ring0/pagetables")); len(vs) != 1 {
		t.Errorf("systrap must not gain pagetables: %d violations, want 1", len(vs))
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/whpx/stub_test.go", importLines("golang.org/x/arch/x86/x86asm")); len(vs) != 0 {
		t.Errorf("whpx test disassembly flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/whpx/stub.go", importLines("golang.org/x/arch/x86/x86asm")); len(vs) != 1 {
		t.Errorf("whpx production code must not import x/arch: %d violations, want 1", len(vs))
	}
}

func TestShimControlInteropImportsStayTestOnly(t *testing.T) {
	t.Parallel()
	imports := importLines("github.com/containerd/containerd/v2/core/runtime/v2", "github.com/containerd/containerd/v2/client", "github.com/containerd/typeurl/v2", "github.com/opencontainers/runtime-spec/specs-go")
	if vs := boundaryCheck(t, "internal/gvxshim/interop_linux_test.go", imports); len(vs) != 0 {
		t.Errorf("upstream interop test imports flagged: %v", vs)
	}
	if vs := boundaryCheck(t, "internal/gvxshim/lifecycle.go", imports); len(vs) != 4 {
		t.Errorf("production interop imports: %d violations, want 4", len(vs))
	}
}

func TestBoundaryNormalizesTheEmbeddedXSysUnix(t *testing.T) {
	const embedded = "z.gfire.dev/gvx/internal/xsys/unix"
	if got := normalizeImport(embedded); got != "golang.org/x/sys/unix" {
		t.Fatalf("normalizeImport(%q) = %q, want the upstream path", embedded, got)
	}
	// A rule that allows x/sys/unix allows the embedded copy, and a rule that
	// does not allow it still refuses the copy.
	if vs := boundaryCheck(t, "pkg/hostlockdown/lockdown_darwin.go", importLines(embedded)); len(vs) != 0 {
		t.Errorf("hostlockdown imports the embedded unix package: %d violations, want 0: %v", len(vs), vs)
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/whpx/whpx.go", importLines(embedded)); len(vs) != 1 {
		t.Errorf("whpx imports the embedded unix package: %d violations, want 1", len(vs))
	}
}

func TestVerifyBoundariesLiveRepository(t *testing.T) {
	t.Parallel()

	start := time.Now()
	report, err := VerifyBoundaries(BoundaryConfig{RootDir: "../.."})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("VerifyBoundaries(../..) failed: %v", err)
	}
	t.Logf("verified %d files (%d Tier 1 pkgs, %d Tier 2 pkgs) in %v",
		report.VerifiedFiles, len(report.Tier1Packages), len(report.Tier2Packages), elapsed)

	if len(report.Tier1Packages) < 60 {
		t.Errorf("discovered %d Tier 1 packages, want at least 60", len(report.Tier1Packages))
	}
	if len(report.Tier2Packages) < 45 {
		t.Errorf("discovered %d Tier 2 packages, want at least 45", len(report.Tier2Packages))
	}
	if report.VerifiedFiles < 3000 {
		t.Errorf("verified %d Go files, want at least 3000", report.VerifiedFiles)
	}
	if slices.Contains(report.Tier1Packages, "tools/shiminterop") {
		t.Errorf("isolated tools/shiminterop module appeared in root Tier 1 package list")
	}
	for _, pkg := range append(slices.Clone(report.Tier1Packages), report.Tier2Packages...) {
		if strings.Contains(pkg, "testdata") {
			t.Errorf("testdata directory %q appeared in discovered packages", pkg)
		}
	}
	for _, rule := range boundaryRules {
		if rule.tier == Tier2Sibling && !slices.Contains(report.Tier2Packages, rule.pkg) {
			t.Errorf("stale Tier 2 rule %q matches no discovered Tier 2 package", rule.pkg)
		}
	}
}

func TestVerifyBoundariesFailsClosedOnUncoveredPackages(t *testing.T) {
	t.Parallel()

	upstream := &UpstreamTree{
		SHA: testSHA,
		Files: map[string][]byte{
			"pkg/rand/rng.go":              []byte("package rand\n"),
			"pkg/sentry/kernel/kernel.go":  []byte("package kernel\n"),
			"pkg/sentry/kernel/futex/f.go": []byte("package futex\n"),
			"pkg/sync/mutex.go":            []byte("package sync\n"),
			"tools/checklocks/analyzer.go": []byte("package checklocks\n"),
		},
	}

	cases := []struct {
		name     string
		files    map[string]string
		wantPkg  string
		wantTier IsolationTier
	}{
		{
			name:     "unlisted Tier 1 package under internal",
			files:    map[string]string{"internal/unlistedprobe/probe.go": "package unlistedprobe\n"},
			wantPkg:  "internal/unlistedprobe",
			wantTier: Tier1Additive,
		},
		{
			name:     "unlisted Tier 1 command under cmd",
			files:    map[string]string{"cmd/unlistedcli/main.go": "package main\n"},
			wantPkg:  "cmd/unlistedcli",
			wantTier: Tier1Additive,
		},
		{
			name:     "unlisted Tier 1 subpackage under pkg/gvx",
			files:    map[string]string{"pkg/gvx/unlistedsub/sub.go": "package unlistedsub\n"},
			wantPkg:  "pkg/gvx/unlistedsub",
			wantTier: Tier1Additive,
		},
		{
			name:     "purely additive Tier 1 package outside tier1Prefixes and upstream",
			files:    map[string]string{"pkg/unlistedadditive/add.go": "package unlistedadditive\n"},
			wantPkg:  "pkg/unlistedadditive",
			wantTier: Tier1Additive,
		},
		{
			name: "unlisted Tier 2 xplat sibling in shared upstream package",
			files: map[string]string{
				"pkg/rand/rng.go":       "package rand\n",
				"pkg/rand/rng_xplat.go": "package rand\n",
			},
			wantPkg:  "pkg/rand",
			wantTier: Tier2Sibling,
		},
		{
			name: "unlisted Tier 2 windows sibling under parent subtree rule",
			files: map[string]string{
				"pkg/sentry/kernel/futex/f.go":         "package futex\n",
				"pkg/sentry/kernel/futex/f_windows.go": "package futex\n",
			},
			wantPkg:  "pkg/sentry/kernel/futex",
			wantTier: Tier2Sibling,
		},
		{
			name: "windows arm64 only Tier 1 package discovered across five targets",
			files: map[string]string{
				"internal/winarmonly/only.go": "//go:build windows && arm64\n\npackage winarmonly\n",
			},
			wantPkg:  "internal/winarmonly",
			wantTier: Tier1Additive,
		},
		{
			name: "darwin arm64 only Tier 2 sibling discovered across five targets",
			files: map[string]string{
				"pkg/rand/rng.go":        "package rand\n",
				"pkg/rand/rng_darwin.go": "//go:build darwin && arm64\n\npackage rand\n",
			},
			wantPkg:  "pkg/rand",
			wantTier: Tier2Sibling,
		},
		{
			name: "linux cgo only Tier 1 package discovered across cgo states",
			files: map[string]string{
				"internal/cgonly/only.go": "//go:build linux && cgo\n\npackage cgonly\n",
			},
			wantPkg:  "internal/cgonly",
			wantTier: Tier1Additive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			for rel, body := range tc.files {
				writeTestFile(t, root, rel, body)
			}
			_, err := VerifyBoundaries(BoundaryConfig{RootDir: root, Upstream: upstream})
			if !errors.Is(err, errUncoveredPackage) {
				t.Fatalf("VerifyBoundaries err = %v, want %v", err, errUncoveredPackage)
			}
			var uncov UncoveredPackageError
			if !errors.As(err, &uncov) {
				t.Fatalf("err %v does not unwrap to UncoveredPackageError", err)
			}
			if uncov.Package != tc.wantPkg || uncov.Tier != tc.wantTier {
				t.Fatalf("got uncovered %+v, want Package=%q Tier=%v", uncov, tc.wantPkg, tc.wantTier)
			}
			if !strings.Contains(err.Error(), tc.wantPkg) {
				t.Fatalf("error %q omits package path %q", err.Error(), tc.wantPkg)
			}
		})
	}

	t.Run("RunAudit fails closed on uncovered package", func(t *testing.T) {
		t.Parallel()
		_, err := auditFixture{
			upstream: baseUpstream(),
			repo:     with(cleanRepo(), "pkg/unlistedadditive/add.go", "package unlistedadditive\n"),
		}.run(t)
		if !errors.Is(err, errUncoveredPackage) || !strings.Contains(err.Error(), "pkg/unlistedadditive") {
			t.Fatalf("RunAudit err = %v, want errUncoveredPackage naming pkg/unlistedadditive", err)
		}
	})

	t.Run("ignored files testdata isolated modules and test-only siblings pass", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		for rel, body := range map[string]string{
			"internal/unlistedignored/ig.go":          "//go:build ignore\n\npackage main\n",
			"pkg/sync/testdata/unlisted/fixture.go":   "package unlisted\n",
			"docs/probes/submod/go.mod":               "module submod\n\ngo 1.27.4\n",
			"docs/probes/submod/main.go":              "package main\n",
			"tools/shiminterop/go.mod":                "module z.gfire.dev/gvx/tools/shiminterop\n\ngo 1.27.4\n",
			"tools/shiminterop/interop_linux_test.go": "package shiminterop\n",
			"pkg/rand/rng.go":                         "package rand\n",
			"pkg/rand/rng_xplat_test.go":              "package rand\n",
			"tools/checklocks/analyzer.go":            "package checklocks\n",
		} {
			writeTestFile(t, root, rel, body)
		}
		report, err := VerifyBoundaries(BoundaryConfig{RootDir: root, Upstream: upstream})
		if err != nil {
			t.Fatalf("VerifyBoundaries returned unexpected error: %v", err)
		}
		if len(report.Tier1Packages) != 0 || len(report.Tier2Packages) != 0 {
			t.Fatalf("unexpected discovered packages: tier1=%v tier2=%v", report.Tier1Packages, report.Tier2Packages)
		}
	})
}

func TestVerifyBoundariesEnforcesArchitecturalRules(t *testing.T) {
	t.Parallel()

	m := modulePrefix
	forbiddenCases := []struct {
		name string
		file string
		imp  string
	}{
		{"gvxshim importing pkg/gvx", "internal/gvxshim/service.go", m + "pkg/gvx"},
		{"gvxshim importing pkg/sentry", "internal/gvxshim/service.go", m + "pkg/sentry/kernel"},
		{"gvxshim importing pkg/hostlockdown", "internal/gvxshim/service.go", m + "pkg/hostlockdown"},
		{"gvxshim importing upstream runsc", "internal/gvxshim/service.go", m + "runsc/boot"},
		{"shim binary importing pkg/gvx", "cmd/containerd-shim-gvx-v2/main.go", m + "pkg/gvx"},
		{"shim binary importing pkg/sentry", "cmd/containerd-shim-gvx-v2/main.go", m + "pkg/sentry/kernel"},
		{"shim binary importing pkg/hostlockdown", "cmd/containerd-shim-gvx-v2/main.go", m + "pkg/hostlockdown"},
		{"pkg/gvx importing internal/gvxshim", "pkg/gvx/sandbox.go", m + "internal/gvxshim"},
		{"pkg/gvx importing cmd/rungv", "pkg/gvx/sandbox.go", m + "cmd/rungv"},
		{"pkg/hostlockdown importing pkg/gvx", "pkg/hostlockdown/lockdown.go", m + "pkg/gvx"},
		{"pkg/hostlockdown importing pkg/sentry", "pkg/hostlockdown/lockdown.go", m + "pkg/sentry/kernel"},
		{"pkg/hostlockdown importing pkg/tcpip", "pkg/hostlockdown/lockdown.go", m + "pkg/tcpip"},
		{"pkg/hostlockdown importing pkg/oci", "pkg/hostlockdown/lockdown.go", m + "pkg/oci"},
		{"pkg/hostlockdown importing pkg/netbackend", "pkg/hostlockdown/lockdown.go", m + "pkg/netbackend"},
		{"pkg/netbackend importing pkg/sentry/kernel", "pkg/netbackend/nat.go", m + "pkg/sentry/kernel"},
		{"pkg/netbackend importing pkg/gvx", "pkg/netbackend/nat.go", m + "pkg/gvx"},
		{"pkg/netbackend importing cmd/rungv", "pkg/netbackend/nat.go", m + "cmd/rungv"},
		{"pkg/oci importing google.golang.org/grpc", "pkg/oci/pull.go", "google.golang.org/grpc"},
		{"pkg/oci importing containerd", "pkg/oci/pull.go", "github.com/containerd/containerd/v2/client"},
		{"pkg/oci importing pkg/sentry", "pkg/oci/pull.go", m + "pkg/sentry/kernel"},
		{"pkg/oci importing pkg/gvx", "pkg/oci/pull.go", m + "pkg/gvx"},
		{"pkg/ipset importing pkg/sentry", "pkg/ipset/ipset.go", m + "pkg/sentry/kernel"},
		{"pkg/ipset importing pkg/gvx", "pkg/ipset/ipset.go", m + "pkg/gvx"},
		{"pkg/tcpip/link/vxlan importing pkg/sentry", "pkg/tcpip/link/vxlan/vxlan.go", m + "pkg/sentry/kernel"},
		{"pkg/tcpip/link/wgtun importing pkg/gvx", "pkg/tcpip/link/wgtun/wgtun.go", m + "pkg/gvx"},
		{"hvcommon importing pkg/gvx", "pkg/sentry/platform/hvcommon/arm64.go", m + "pkg/gvx"},
		{"hvf importing pkg/oci", "pkg/sentry/platform/hvf/hvf.go", m + "pkg/oci"},
		{"whpx importing pkg/netbackend", "pkg/sentry/platform/whpx/whpx.go", m + "pkg/netbackend"},
		{"runtime pkg importing tools", "pkg/sync/mutex.go", m + "tools/upstream"},
		{"runtime pkg importing e2e", "pkg/sentry/vfs/vfs.go", m + "e2e"},
		{"runtime pkg importing cmd", "pkg/sentry/vfs/vfs.go", m + "cmd/rungv"},
		{"pkg/sync xplat sibling importing pkg/sentry/kernel", "pkg/sync/futex_xplat.go", m + "pkg/sentry/kernel"},
		{"pkg/ring0 windows sibling importing pkg/sentry/arch", "pkg/ring0/bluepill_windows.go", m + "pkg/sentry/arch"},
		{"Tier 2 sibling importing pkg/gvx", "pkg/sentry/mm/mm_xplat.go", m + "pkg/gvx"},
		{"Tier 2 sibling importing pkg/oci", "pkg/sentry/mm/mm_xplat.go", m + "pkg/oci"},
		{"Tier 2 sibling importing pkg/netbackend", "pkg/sentry/mm/mm_xplat.go", m + "pkg/netbackend"},
		{"Tier 2 sibling importing pkg/hostlockdown", "pkg/sentry/mm/mm_xplat.go", m + "pkg/hostlockdown"},
		{"Tier 2 sibling importing internal/gvxshim", "pkg/sentry/mm/mm_xplat.go", m + "internal/gvxshim"},
		{"Tier 2 sibling importing cmd", "pkg/sentry/mm/mm_xplat.go", m + "cmd/rungv"},
	}

	for _, tc := range forbiddenCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if ClassifyFile(tc.file) == Tier2Sibling {
				writeTestFile(t, root, filepath.ToSlash(filepath.Join(filepath.Dir(tc.file), "upstream.go")), "package p\n")
			}
			writeTestFile(t, root, tc.file, importLines(tc.imp))
			_, err := VerifyBoundaries(BoundaryConfig{RootDir: root})
			if !errors.Is(err, errForbiddenImport) {
				t.Fatalf("VerifyBoundaries(%s importing %s) err = %v, want %v", tc.file, tc.imp, err, errForbiddenImport)
			}
		})
	}

	t.Run("netbackend allows leaf pkg/gvx/tuning and Tier 3 ring0 allows pkg/sentry/arch", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeTestFile(t, root, "pkg/netbackend/nat.go", importLines(m+"pkg/gvx/tuning"))
		writeTestFile(t, root, "pkg/ring0/defs.go", importLines(m+"pkg/sentry/arch"))
		writeTestFile(t, root, "pkg/ring0/bluepill_windows.go", "package p\n")
		if _, err := VerifyBoundaries(BoundaryConfig{RootDir: root}); err != nil {
			t.Fatalf("VerifyBoundaries returned unexpected error: %v", err)
		}
	})
}
