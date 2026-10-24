package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

// importRule encodes one row of the import directionality table in docs/architecture.md section 2.1.
//
// Forbidden entries apply to every file under the package tree. Allowed entries apply to
// files that gvx wrote (Tier 1 and Tier 2). Upstream-authored Tier 3 files are bound by the
// forbidden list only, because the Tier 3 diff budget already governs their content.
type importRule struct {
	// pkg is the repository-relative package directory. The rule covers its whole subtree.
	pkg string
	// allowed lists the SPEC "Allowed Internal Imports" column.
	allowed []string
	// forbidden lists the SPEC "Forbidden Imports" column plus implied host-API bans.
	forbidden []string
	// forbiddenLiterals lists string literals that must not appear in the package.
	forbiddenLiterals []string
	// skipTrees lists subtrees of pkg that another rule governs instead.
	skipTrees []string
}

// importException permits one import that the SPEC table does not list.
// Every entry names the architectural reason. An entry never overrides a forbidden match.
type importException struct {
	pkgs   []string
	prefix string
	reason string
}

// A pattern ending in "/*" matches the named path and every path below it.
// Any other pattern matches exactly one import path.
//
// The SPEC rows for platform backends list "pkg/sentry/platform" as one package. Backends must
// not import each other, so the tree pattern is written out with explicit sibling bans.
var platformSiblings = []string{
	"pkg/sentry/platform/hvf",
	"pkg/sentry/platform/whpx",
	"pkg/sentry/platform/systrap",
	"pkg/sentry/platform/kvm",
	"pkg/sentry/platform/ptrace",
	"pkg/sentry/platform/slimvm",
}

const (
	pkgSentryAll = "pkg/sentry/*"
	xSysWindows  = "golang.org/x/sys/windows/*"
	xSysUnix     = "golang.org/x/sys/unix/*"
	winHvDLL     = "WinHvPlatform.dll"
)

var boundaryRules = []importRule{
	{
		pkg: "tools/shiminterop",
		allowed: []string{
			"github.com/containerd/containerd/api/runtime/*",
			"github.com/containerd/containerd/v2/core/runtime/*",
			"github.com/containerd/containerd/v2/core/events/exchange",
			"github.com/containerd/containerd/v2/pkg/namespaces",
			"github.com/containerd/errdefs", "github.com/containerd/typeurl/v2",
			"github.com/opencontainers/runtime-spec/specs-go",
			"golang.org/x/sys/unix", "google.golang.org/grpc/*",
		},
		forbidden: []string{"pkg/*", "internal/*", "cmd/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "cmd/containerd-shim-gvx-v2",
		allowed:   []string{"internal/gvxshim"},
		forbidden: []string{"pkg/*", "runsc/*", "shim/*"},
	},
	{
		pkg: "internal/gvxshim",
		allowed: []string{
			"golang.org/x/sys/*", "github.com/Microsoft/go-winio",
			"github.com/containerd/containerd/api/runtime/*",
			"github.com/containerd/containerd/v2/pkg/identifiers",
			"github.com/containerd/containerd/v2/pkg/namespaces",
			"github.com/containerd/ttrpc", "google.golang.org/grpc/*", "google.golang.org/protobuf/*",
			"github.com/sirupsen/logrus",
			"github.com/containerd/log",
		},
		forbidden: []string{"pkg/*", "runsc/*", "shim/*", "cmd/*"},
	},
	{
		pkg:               "cmd/rungv",
		allowed:           []string{"pkg/gvx", "pkg/oci"},
		forbidden:         []string{pkgSentryAll},
		forbiddenLiterals: []string{winHvDLL},
	},
	{
		pkg:       "pkg/gvx",
		allowed:   []string{"pkg/oci", "pkg/netbackend", "pkg/hostlockdown", pkgSentryAll, "pkg/fd", "pkg/tcpip/*"},
		forbidden: []string{"cmd/*", "internal/gvxshim/*"},
	},
	{
		pkg:       "pkg/oci",
		allowed:   []string{"pkg/abi/linux"},
		forbidden: []string{"pkg/sentry/kernel/*", "pkg/hostlockdown", "cmd/*"},
	},
	{
		pkg:               "pkg/netbackend",
		allowed:           []string{"pkg/tcpip/*"},
		forbidden:         []string{"pkg/sentry/kernel/*", "cmd/*"},
		forbiddenLiterals: []string{winHvDLL},
	},
	{
		pkg:       "pkg/hostlockdown",
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: []string{pkgSentryAll, "pkg/tcpip/*", "cmd/*"},
	},
	{
		pkg:       "pkg/sentry/kernel",
		allowed:   []string{"pkg/abi/linux", "pkg/sentry/platform", "pkg/sentry/vfs", "pkg/sync"},
		forbidden: []string{xSysWindows, "pkg/hostlockdown", "cmd/*"},
	},
	{
		pkg:       "pkg/sentry/platform/whpx",
		allowed:   []string{"pkg/sentry/platform", "pkg/sentry/platform/hvcommon", "pkg/memutil", "pkg/abi/linux", xSysWindows},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "cmd/*"}, without(platformSiblings, "pkg/sentry/platform/whpx")...),
	},
	{
		pkg:       "pkg/sentry/platform/hvf",
		allowed:   []string{"pkg/sentry/platform", "pkg/sentry/platform/hvcommon", "pkg/memutil", "pkg/abi/linux", xSysUnix},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "cmd/*"}, without(platformSiblings, "pkg/sentry/platform/hvf")...),
	},
	{
		pkg:       "pkg/sentry/platform/systrap",
		allowed:   []string{"pkg/sentry/platform", "pkg/memutil", "pkg/abi/linux", "golang.org/x/arch/*"},
		forbidden: []string{"pkg/sentry/kernel/*", "pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "cmd/*"},
		// usertrap is upstream code. It reads guest memory through kernel.Task, so
		// its own rule below keeps the other bans and drops the kernel ban.
		skipTrees: []string{"pkg/sentry/platform/systrap/usertrap"},
	},
	{
		pkg:       "pkg/sentry/platform/systrap/usertrap",
		forbidden: []string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "cmd/*"},
	},
	{
		pkg:       "pkg/sentry/fsimpl/hostfs",
		allowed:   []string{"pkg/sentry/vfs", "pkg/abi/linux", "pkg/fd", "golang.org/x/sys/*"},
		forbidden: []string{"pkg/sentry/platform/*", "cmd/*"},
	},
	{
		// ext4lite is a read-write VFS2 filesystem in a single host file. It
		// implements the same VFS interfaces as hostfs, so it gets the same
		// import surface, and it must not reach a platform backend.
		pkg:       "pkg/sentry/fsimpl/ext4lite",
		allowed:   []string{"pkg/sentry/vfs", "pkg/abi/linux", "pkg/fd", "golang.org/x/sys/*"},
		forbidden: []string{"pkg/sentry/platform/*", "cmd/*"},
	},
	{
		// hvcommon holds the pure helpers that whpx and hvf share. It must not
		// import a backend, the kernel, or the VFS.
		pkg:       "pkg/sentry/platform/hvcommon",
		allowed:   []string{"pkg/sentry/platform", "pkg/abi/linux"},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "cmd/*"}, platformSiblings...),
	},
	{
		pkg:       "pkg/sync",
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: []string{pkgSentryAll, "cmd/*"},
	},
	{
		pkg:       "pkg/memutil",
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: []string{pkgSentryAll, "cmd/*"},
	},
	{
		pkg:       "pkg/fd",
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: []string{pkgSentryAll, "cmd/*"},
	},
}

func without(list []string, drop string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

// sentryAPIUsers lists the gvx-written packages that implement or call Sentry interfaces.
var sentryAPIUsers = []string{
	"pkg/gvx",
	"pkg/sentry/fsimpl/hostfs",
	"pkg/sentry/fsimpl/ext4lite",
	"pkg/sentry/platform/whpx",
	"pkg/sentry/platform/hvf",
	"pkg/sentry/platform/systrap",
}

var platformBackends = []string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/systrap"}

// boundaryExceptions is the complete list of imports that the SPEC table does not name.
// Add an entry only when the Go type system or an upstream interface forces the import.
var boundaryExceptions = []importException{
	// Sentry foundation packages appear in the signatures of the kernel, VFS, and platform interfaces.
	{sentryAPIUsers, "pkg/context", "Sentry entry points take context.Context"},
	{sentryAPIUsers, "pkg/hostarch", "Sentry address and page types live in pkg/hostarch"},
	{sentryAPIUsers, "pkg/usermem", "guest memory I/O uses usermem.IO and usermem.IOOpts"},
	{sentryAPIUsers, "pkg/sentry/memmap", "platform and VFS memory mapping interfaces use memmap types"},
	{sentryAPIUsers, "pkg/errors/linuxerr", "VFS and kernel calls return linuxerr values"},
	{sentryAPIUsers, "pkg/fspath", "VFS path operations use fspath.Path"},
	{sentryAPIUsers, "pkg/safemem", "VFS reads and writes use safemem block sequences"},
	{sentryAPIUsers, "pkg/atomicbitops", "dentry and option words are atomic upstream types"},
	{sentryAPIUsers, "pkg/log", "upstream logging package"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/systrap"}, "pkg/sentry/arch", "platform.Context.Switch exchanges arch.Context64 values"},
	{platformBackends, "pkg/sentry/platform/interrupt", "platform.Context.Switch callers wake a running vCPU through interrupt.Forwarder"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf"}, "pkg/ring0/pagetables", "hardware backends build guest stage-1 and stage-2 page tables with the shared pagetables package"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite"}, "pkg/sentry/kernel/auth", "vfs.FilesystemImpl methods take auth.Credentials"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite"}, "pkg/sentry/limits", "vfs write paths consult limits.FileSize"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite"}, "pkg/sentry/socket/unix/transport", "vfs.FilesystemImpl.BoundEndpointAt returns transport.BoundEndpoint"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite"}, "pkg/refs", "vfs.DentryImpl reference counting uses refs.RefCounter"},
	{[]string{"pkg/sentry/platform/systrap"}, "golang.org/x/sys/*", "host memory and subprocess APIs on Windows and macOS (SPEC section 3.3)"},
	{[]string{"pkg/sentry/kernel"}, "pkg/hostarch", "addrhole_xplat.go lists the address holes of a platform as hostarch.AddrRange values"},

	// pkg/gvx boots the Sentry. The kernel constructors take these types.
	{[]string{"pkg/gvx"}, "pkg/abi/linux", "Linux ABI constants for guest syscall numbers and errno values"},
	{[]string{"pkg/gvx"}, "pkg/cpuid", "kernel.Init requires a cpuid.FeatureSet"},
	{[]string{"pkg/gvx"}, "pkg/marshal/primitive", "guest memory copies use primitive marshal types"},
	{[]string{"pkg/gvx"}, "pkg/memutil", "kernel memory files need host memory views"},

	// pkg/netbackend: Netstack's own foundation packages sit outside the pkg/tcpip tree.
	{[]string{"pkg/netbackend"}, "pkg/buffer", "pkg/tcpip packets are pkg/buffer.Buffer values"},
	{[]string{"pkg/netbackend"}, "pkg/waiter", "pkg/tcpip endpoints signal readiness through pkg/waiter queues"},
	{[]string{"pkg/netbackend"}, "golang.zx2c4.com/wireguard/*", "SPEC section 3.5 Track B embeds wireguard-go"},
	{[]string{"pkg/netbackend"}, "golang.org/x/sys/*", "host DNS resolver discovery needs GetAdaptersAddresses on Windows and the resolver configuration on macOS"},

	// pkg/gvx: the Linux lockdown reuses the seccomp allowlist of the gVisor Sentry.
	{[]string{"pkg/gvx"}, "runsc/boot/filter/config", "the Linux lockdown installs the runsc Sentry allowlist"},
	{[]string{"pkg/gvx"}, "pkg/seccomp", "the Linux lockdown builds the seccomp program with the upstream rule types"},
	{[]string{"pkg/gvx"}, "golang.org/x/sys/unix", "the Linux lockdown names system calls for the extra rules"},
	// pkg/oci: the EROFS writer and the layer codecs have no SPEC row of their own.
	{[]string{"pkg/oci"}, "pkg/erofs", "SPEC section 3.6 compiles layer tarballs with the upstream erofs ABI"},
	{[]string{"pkg/oci"}, "github.com/klauspost/compress/*", "zstd-compressed OCI layers"},
	{[]string{"pkg/oci"}, "github.com/cespare/xxhash/*", "content-addressed layer cache keys"},
	{[]string{"pkg/oci"}, "golang.org/x/sys/*", "the Windows layer cache opens files with full sharing and renames with POSIX semantics"},
}

// boundaryTestExceptions apply to _test.go files only.
var boundaryTestExceptions = []importException{
	{[]string{"internal/gvxshim"}, "github.com/containerd/containerd/v2/*", "interop tests exercise the pinned containerd lifecycle and private daemon"},
	{[]string{"internal/gvxshim"}, "github.com/containerd/typeurl/v2", "interop tests marshal a real OCI specification"},
	{[]string{"internal/gvxshim"}, "github.com/containerd/errdefs", "interop tests assert native unsupported-operation errors"},
	{[]string{"internal/gvxshim"}, "github.com/opencontainers/runtime-spec/specs-go", "interop tests supply a minimal OCI specification without a workload"},
	{[]string{"pkg/gvx", "cmd/rungv"}, "internal/*", "gvx-owned guest ELF and image fixtures for tests"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/hvcommon"}, "golang.org/x/arch/*", "tests disassemble the generated guest stubs"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/sentry/pgalloc", "tests back the chunks of mapped files with a memory file, as pkg/gvx does on Linux"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/memutil", "tests create the memfd of the memory file that backs chunks"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/sentry/usage", "pgalloc.AllocOpts takes a usage.MemoryKind"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/sentry/uniqueid", "vfs.Init in tests needs a uniqueid.Provider on the context"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/errors", "tests compare errors.Error values from the VFS"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/systrap"}, "pkg/cpuid", "arch.Context64 and the CPUID trap path need cpuid.Initialize before a test builds a context"},
	{[]string{"pkg/sentry/platform/systrap", "pkg/sentry/platform/hvf"}, "pkg/sentry/pgalloc", "tests build the pgalloc.MemoryFile that backs guest pages"},
	{[]string{"pkg/sentry/platform/systrap", "pkg/sentry/platform/hvf"}, "pkg/sentry/usage", "pgalloc.AllocOpts takes a usage.MemoryKind"},
	{[]string{"pkg/hostlockdown"}, "pkg/seccomp", "tests install a small seccomp program through Options.InstallSyscallFilter"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/hostlockdown", "a test proves that the stub keeps working after hostlockdown.Apply"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/loader/vdsodata", "a test pins that the vDSO image that the Sentry maps never names x18"},
}

func exceptionApplies(ex importException, pkg, imp string) bool {
	return slices.Contains(ex.pkgs, pkg) && matchImportPattern(ex.prefix, imp)
}

// BoundaryViolation describes one import that crosses a SPEC boundary.
type BoundaryViolation struct {
	File    string
	Import  string
	Package string
	Reason  string
}

func (v BoundaryViolation) Error() string {
	return fmt.Sprintf("%s imports %s: %s (boundary %s)", v.File, v.Import, v.Reason, v.Package)
}

func (v BoundaryViolation) Unwrap() error { return errForbiddenImport }

// normalizeImport strips the module prefixes and returns the repository-relative import path.
func normalizeImport(impPath string) string {
	trimmed := strings.TrimPrefix(impPath, modulePrefix)
	return strings.TrimPrefix(trimmed, legacyModulePrefix)
}

func isStdlibImport(impPath string) bool {
	first, _, _ := strings.Cut(impPath, "/")
	return !strings.Contains(first, ".")
}

// matchImportPattern reports whether imp (module-relative or external) matches pattern.
func matchImportPattern(pattern, imp string) bool {
	if base, ok := strings.CutSuffix(pattern, "/*"); ok {
		return imp == base || strings.HasPrefix(imp, base+"/")
	}
	return imp == pattern
}

func matchAny(patterns []string, imp string) (string, bool) {
	for _, p := range patterns {
		if matchImportPattern(p, imp) {
			return p, true
		}
	}
	return "", false
}

func inTree(pkgDir, tree string) bool {
	return pkgDir == tree || strings.HasPrefix(pkgDir, tree+"/")
}

// checkImports validates the imports and string literals of one parsed file.
func checkImports(relSlash string, tier IsolationTier, file *ast.File) []BoundaryViolation {
	pkgDir := path.Dir(relSlash)
	var out []BoundaryViolation
	for _, rule := range boundaryRules {
		if !inTree(pkgDir, rule.pkg) || slices.ContainsFunc(rule.skipTrees, func(tree string) bool { return inTree(pkgDir, tree) }) {
			continue
		}
		for _, spec := range file.Imports {
			impPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				out = append(out, BoundaryViolation{File: relSlash, Import: spec.Path.Value, Package: rule.pkg, Reason: "unquotable import path"})
				continue
			}
			if v, bad := checkOneImport(relSlash, pkgDir, tier, rule, impPath); bad {
				out = append(out, v)
			}
		}
		if len(rule.forbiddenLiterals) > 0 {
			out = append(out, checkLiterals(relSlash, rule, file)...)
		}
	}
	return out
}

func checkOneImport(relSlash, pkgDir string, tier IsolationTier, rule importRule, impPath string) (BoundaryViolation, bool) {
	if isStdlibImport(impPath) || impPath == "C" {
		return BoundaryViolation{}, false
	}
	imp := normalizeImport(impPath)
	if pattern, bad := matchAny(rule.forbidden, imp); bad {
		return BoundaryViolation{File: relSlash, Import: impPath, Package: rule.pkg, Reason: "forbidden by SPEC 2.1 (" + pattern + ")"}, true
	}
	if tier == Tier3Upstream {
		return BoundaryViolation{}, false
	}
	if inTree(imp, rule.pkg) || inTree(imp, pkgDir) {
		return BoundaryViolation{}, false
	}
	if _, ok := matchAny(rule.allowed, imp); ok {
		return BoundaryViolation{}, false
	}
	exceptions := boundaryExceptions
	if strings.HasSuffix(relSlash, "_test.go") {
		exceptions = append(slices.Clone(exceptions), boundaryTestExceptions...)
	}
	for _, ex := range exceptions {
		if exceptionApplies(ex, rule.pkg, imp) {
			return BoundaryViolation{}, false
		}
	}
	return BoundaryViolation{File: relSlash, Import: impPath, Package: rule.pkg, Reason: "not in the SPEC 2.1 allowed list and not a registered exception"}, true
}

func checkLiterals(relSlash string, rule importRule, file *ast.File) []BoundaryViolation {
	var out []BoundaryViolation
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		for _, banned := range rule.forbiddenLiterals {
			if strings.Contains(strings.ToLower(value), strings.ToLower(banned)) {
				out = append(out, BoundaryViolation{File: relSlash, Import: strconv.Quote(value), Package: rule.pkg, Reason: "forbidden literal " + banned})
			}
		}
		return true
	})
	return out
}

// auditFileImports parses absPath and returns every boundary violation in it.
//
// SPEC 2.1 keeps Windows and macOS host APIs out of the Sentry. An upstream (Tier 3) file
// that no Priority-0 target compiles cannot break that goal, so its violations do not count.
func auditFileImports(fset *token.FileSet, absPath, relSlash string, tier IsolationTier) ([]BoundaryViolation, error) {
	needsBody := false
	pkgDir := path.Dir(relSlash)
	for _, rule := range boundaryRules {
		if inTree(pkgDir, rule.pkg) {
			needsBody = needsBody || len(rule.forbiddenLiterals) > 0
		}
	}
	mode := parser.ImportsOnly
	if needsBody {
		mode = 0
	}
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relSlash, err)
	}
	file, err := parser.ParseFile(fset, absPath, src, mode)
	if err != nil {
		return nil, fmt.Errorf("parse imports in %s: %w", relSlash, err)
	}
	violations := checkImports(relSlash, tier, file)
	if len(violations) == 0 || tier != Tier3Upstream {
		return violations, nil
	}
	set, err := buildSet(path.Base(relSlash), src, nonLinuxTargets)
	if err != nil {
		return nil, err
	}
	if !anyTrue(set) {
		return nil, nil
	}
	return violations, nil
}
