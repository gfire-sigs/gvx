package main

import (
	"errors"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
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
	for _, file := range []string{"pkg/sentry/platform/whpx/x.go", "pkg/sentry/platform/hvf/x.go"} {
		if vs := boundaryCheck(t, file, importLines(m+"pkg/sentry/platform/hvcommon")); len(vs) != 0 {
			t.Errorf("%s importing hvcommon flagged: %v", file, vs)
		}
	}
	if vs := boundaryCheck(t, "pkg/sentry/platform/systrap/x_xplat.go", importLines(m+"pkg/sentry/platform/hvcommon")); len(vs) != 1 {
		t.Errorf("systrap importing hvcommon: %d violations, want 1", len(vs))
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
