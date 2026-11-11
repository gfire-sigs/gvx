package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

var errUncoveredPackage = errors.New("package matches no import boundary rule")

// UncoveredPackageError reports a Tier 1 or Tier 2 package that lacks an explicit rule.
type UncoveredPackageError struct {
	Package string
	Tier    IsolationTier
}

func (e UncoveredPackageError) Error() string {
	return fmt.Sprintf("uncovered %s package %s: register an explicit rule in tools/upstream/boundaries.go", e.Tier, e.Package)
}

func (e UncoveredPackageError) Unwrap() error { return errUncoveredPackage }

// BoundaryConfig configures import-boundary verification across all five targets.
type BoundaryConfig struct {
	RootDir  string
	Upstream *UpstreamTree
}

// BoundaryReport summarizes discovered Tier 1 and Tier 2 packages and verified files.
type BoundaryReport struct {
	Tier1Packages []string
	Tier2Packages []string
	VerifiedFiles int
}

// allTargets lists the five supported target OS and architecture pairs.
var allTargets = []buildTarget{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

// importRule encodes one architectural import boundary rule.
//
// Forbidden entries apply to every file matched by the rule. Allowed entries apply to
// files that gvx owns (Tier 1 and Tier 2). Upstream Tier 3 files obey the forbidden
// lists, because the Tier 3 diff ceiling already governs their content.
type importRule struct {
	// pkg names the repository-relative package directory.
	pkg string
	// tier identifies whether this rule covers a Tier 1 package, a Tier 2 package, or a Tier 3 fence.
	tier IsolationTier
	// subtree extends import enforcement to subpackages below pkg.
	// Tier 2 package coverage always requires an exact pkg match even when subtree is true.
	subtree bool
	// allowed lists permitted internal and external dependency patterns for Tier 1 and Tier 2 files.
	allowed []string
	// forbidden lists dependency patterns rejected in both production and test files.
	forbidden []string
	// forbiddenExcept exempts narrow leaf packages from broad wildcard entries in forbidden.
	forbiddenExcept []string
	// forbiddenProd lists dependency patterns rejected in non-test files.
	forbiddenProd []string
	// forbiddenTier2 lists dependency patterns rejected in Tier 2 files when upstream Tier 3 files differ.
	forbiddenTier2 []string
	// forbiddenLiterals lists string literals rejected anywhere in the package.
	forbiddenLiterals []string
	// skipTrees lists subtrees below pkg that another rule governs instead.
	skipTrees []string
}

// importException permits one dependency that the primary allowed list omits.
// Every entry states the architectural reason and never overrides a forbidden match.
type importException struct {
	pkgs   []string
	prefix string
	reason string
}

// A pattern ending in "/*" matches the named path and every path below it.
// Any other pattern matches one exact import path.
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

// runtimeOuterBans lists command, shim-adapter, harness, tool, and upstream-CLI trees
// that runtime and library packages under pkg/ must never import.
var runtimeOuterBans = []string{
	"cmd/*",
	"internal/gvxshim/*",
	"e2e/*",
	"tools/*",
	"scripts/*",
	"runsc/*",
	"shim/*",
}

// tier2UpperBans lists upper gvx subsystems plus runtimeOuterBans.
// No Tier 2 sibling file in a shared upstream package may import these trees.
var tier2UpperBans = append([]string{
	"pkg/gvx/*",
	"pkg/oci/*",
	"pkg/netbackend/*",
	"pkg/hostlockdown/*",
}, runtimeOuterBans...)

// lowLevelTier2Bans forbids Sentry and all upper runtime trees in low-level foundation packages.
var lowLevelTier2Bans = append([]string{pkgSentryAll}, tier2UpperBans...)

var boundaryRules = []importRule{
	// Isolated interop module for containerd SDK.
	{
		pkg:     "tools/shiminterop",
		tier:    Tier1Additive,
		subtree: true,
		allowed: []string{
			"github.com/containerd/containerd/api/runtime/*",
			"github.com/containerd/containerd/v2/core/runtime/*",
			"github.com/containerd/containerd/v2/core/events/exchange",
			"github.com/containerd/containerd/v2/pkg/namespaces",
			"github.com/containerd/errdefs", "github.com/containerd/typeurl/v2",
			"github.com/opencontainers/runtime-spec/specs-go",
			"golang.org/x/sys/unix", "google.golang.org/grpc/*",
		},
		forbidden: []string{"pkg/*", "internal/*", "cmd/*", "e2e/*", "tools/upstream/*", "runsc/*", "shim/*"},
	},

	// G3 boundary for containerd shim (AGENTS.md Section 2 and SPEC 2.1).
	{
		pkg:       "cmd/containerd-shim-gvx-v2",
		tier:      Tier1Additive,
		allowed:   []string{"internal/gvxshim"},
		forbidden: []string{"pkg/*", "runsc/*", "shim/*", "e2e/*", "tools/*", "scripts/*"},
	},
	{
		pkg:     "internal/gvxshim",
		tier:    Tier1Additive,
		subtree: true,
		allowed: []string{
			"golang.org/x/sys/*", "github.com/Microsoft/go-winio",
			"github.com/containerd/containerd/api/runtime/*",
			"github.com/containerd/containerd/v2/pkg/identifiers",
			"github.com/containerd/containerd/v2/pkg/namespaces",
			"github.com/containerd/ttrpc", "google.golang.org/grpc/*", "google.golang.org/protobuf/*",
			"github.com/sirupsen/logrus",
			"github.com/containerd/log",
		},
		forbidden: []string{"pkg/*", "runsc/*", "shim/*", "cmd/*", "e2e/*", "tools/*", "scripts/*"},
	},

	// Standalone CLI runner and SDK coordinator (Tier 1).
	{
		pkg:               "cmd/rungv",
		tier:              Tier1Additive,
		allowed:           []string{"pkg/gvx", "pkg/oci"},
		forbidden:         []string{pkgSentryAll, "pkg/hostlockdown/*", "pkg/netbackend/*", "internal/gvxshim/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
		forbiddenLiterals: []string{winHvDLL},
	},
	{
		pkg:       "pkg/gvx",
		tier:      Tier1Additive,
		allowed:   []string{"pkg/oci", "pkg/netbackend", "pkg/hostlockdown", pkgSentryAll, "pkg/fd", "pkg/tcpip/*"},
		forbidden: []string{"cmd/*", "internal/gvxshim/*", "e2e/*", "tools/*", "scripts/*", "shim/*"},
	},
	{
		pkg:       "pkg/gvx/tuning",
		tier:      Tier1Additive,
		forbidden: append([]string{"pkg/gvx", "pkg/gvx/hostcerts/*", pkgSentryAll, "pkg/oci/*", "pkg/netbackend/*", "pkg/hostlockdown/*", "pkg/tcpip/*", "internal/*"}, runtimeOuterBans...),
	},
	{
		pkg:       "pkg/gvx/hostcerts",
		tier:      Tier1Additive,
		forbidden: append([]string{"pkg/gvx", "pkg/gvx/tuning/*", pkgSentryAll, "pkg/oci/*", "pkg/netbackend/*", "pkg/hostlockdown/*", "pkg/tcpip/*", "internal/*"}, runtimeOuterBans...),
	},

	// OCI compiler, network backend, and host lockdown (Tier 1).
	{
		pkg:     "pkg/oci",
		tier:    Tier1Additive,
		subtree: true,
		allowed: []string{
			"pkg/abi/linux",
			"github.com/distribution/reference",
			"github.com/opencontainers/go-digest",
			"github.com/opencontainers/image-spec/*",
		},
		forbidden: append([]string{
			"github.com/containerd/*",
			"google.golang.org/grpc/*",
			"go.opentelemetry.io/*",
			"k8s.io/*",
			pkgSentryAll,
			"pkg/gvx/*",
			"pkg/hostlockdown/*",
			"pkg/netbackend/*",
			"pkg/tcpip/*",
		}, runtimeOuterBans...),
	},
	{
		pkg:               "pkg/netbackend",
		tier:              Tier1Additive,
		subtree:           true,
		allowed:           []string{"pkg/tcpip/*"},
		forbidden:         append([]string{pkgSentryAll, "pkg/gvx/*", "pkg/oci/*", "pkg/hostlockdown/*"}, runtimeOuterBans...),
		forbiddenExcept:   []string{"pkg/gvx/tuning"},
		forbiddenLiterals: []string{winHvDLL},
	},
	{
		pkg:       "pkg/hostlockdown",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: append([]string{"pkg/gvx/*", pkgSentryAll, "pkg/tcpip/*", "pkg/oci/*", "pkg/netbackend/*"}, runtimeOuterBans...),
	},

	// Tier 1 Netstack, VFS, netlink, and hypervisor packages.
	{
		pkg:       "pkg/ipset",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/atomicbitops", "pkg/state", "pkg/tcpip/*"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/tcpip/link/vxlan",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/atomicbitops", "pkg/buffer", "pkg/state", "pkg/sync", "pkg/tcpip/*", "pkg/waiter"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/tcpip/link/wgtun",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/tcpip/*", "pkg/buffer", "pkg/waiter", "golang.zx2c4.com/wireguard/*"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/sentry/blockdev",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/context", "pkg/errors/linuxerr", "pkg/sentry/vfs", "pkg/state", "pkg/sync"},
		forbidden: append([]string{"pkg/sentry/platform/*", "pkg/sentry/kernel/*"}, tier2UpperBans...),
	},
	{
		pkg:           "pkg/sentry/fsimpl/hostfs",
		tier:          Tier1Additive,
		subtree:       true,
		allowed:       []string{"pkg/sentry/vfs", "pkg/sentry/fsimpl/chunkcache", "pkg/sentry/fsimpl/fsutilx", "pkg/abi/linux", "pkg/fd", "golang.org/x/sys/*"},
		forbidden:     append([]string{"pkg/sentry/platform/*"}, without(tier2UpperBans, "pkg/hostlockdown/*")...),
		forbiddenProd: []string{"pkg/hostlockdown/*"},
	},
	{
		pkg:       "pkg/sentry/fsimpl/ext4lite",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/sentry/vfs", "pkg/sentry/blockdev", "pkg/sentry/fsimpl/chunkcache", "pkg/sentry/fsimpl/fsutilx", "pkg/abi/linux", "pkg/fd", "golang.org/x/sys/*"},
		forbidden: append([]string{"pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/fsimpl/chunkcache",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/sentry/vfs", "pkg/sentry/fsimpl/fsutilx", "pkg/state", "pkg/abi/linux", "golang.org/x/sys/*"},
		forbidden: append([]string{"pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/fsimpl/fsutilx",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/sentry/vfs", "pkg/abi/linux"},
		forbidden: append([]string{"pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/platform/whpx",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/sentry/platform", "pkg/sentry/platform/hvcommon", "pkg/memutil", "pkg/abi/linux", xSysWindows},
		forbidden: append(append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*"}, without(platformSiblings, "pkg/sentry/platform/whpx")...), tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/platform/hvf",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/sentry/platform", "pkg/sentry/platform/hvcommon", "pkg/memutil", "pkg/abi/linux", xSysUnix},
		forbidden: append(append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*"}, without(platformSiblings, "pkg/sentry/platform/hvf")...), tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/platform/hvcommon",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"pkg/sentry/platform", "pkg/abi/linux"},
		forbidden: append(append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*"}, platformSiblings...), tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/socket/netlink/genetlink",
		tier:      Tier1Additive,
		allowed:   []string{"pkg/abi/linux", "pkg/context", "pkg/marshal/primitive", "pkg/sentry/kernel", "pkg/sentry/socket/netlink", "pkg/sentry/socket/netlink/nlmsg", "pkg/state", "pkg/sync", "pkg/syserr"},
		forbidden: append([]string{xSysWindows, xSysUnix, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/socket/netlink/genetlink/wireguard",
		tier:      Tier1Additive,
		allowed:   []string{"golang.zx2c4.com/wireguard/*", "pkg/abi/linux", "pkg/atomicbitops", "pkg/buffer", "pkg/context", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/log", "pkg/marshal/primitive", "pkg/sentry/kernel", "pkg/sentry/kernel/auth", "pkg/sentry/socket/netlink/genetlink", "pkg/sentry/socket/netlink/nlmsg", "pkg/sentry/socket/netstack", "pkg/sentry/usage", "pkg/state", "pkg/sync", "pkg/syserr", "pkg/tcpip/*", "pkg/waiter"},
		forbidden: append([]string{xSysWindows, xSysUnix, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},

	// Tier 1 black-box test suite, internal probes/fixtures, scripts, and repository tools.
	{
		pkg:       "e2e",
		tier:      Tier1Additive,
		allowed:   []string{xSysWindows},
		forbidden: []string{"cmd/*", "internal/gvxshim/*", "tools/*", "scripts/*", "runsc/*", "shim/*", "pkg/sentry/kernel/*", "pkg/sentry/platform/*", "pkg/hostlockdown/*"},
	},
	{
		pkg:       "internal/weakmap",
		tier:      Tier1Additive,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "internal/xsys",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: []string{"pkg/*", "cmd/*", "internal/gvxshim/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "internal/acceptprog",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{xSysUnix, "github.com/vishvananda/netlink/*"},
		forbidden: []string{"pkg/*", "cmd/*", "internal/gvxshim/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "internal/hvtest",
		tier:      Tier1Additive,
		allowed:   []string{"pkg/sentry/platform/hvf", "pkg/sentry/platform/whpx"},
		forbidden: append([]string{"pkg/sentry/kernel/*"}, tier2UpperBans...),
	},
	{
		pkg:       "internal/systraptest",
		tier:      Tier1Additive,
		allowed:   []string{"pkg/sentry/platform", "pkg/sentry/platform/systrap"},
		forbidden: append([]string{"pkg/sentry/kernel/*"}, tier2UpperBans...),
	},
	{
		pkg:       "internal/lockdownprobe",
		tier:      Tier1Additive,
		allowed:   []string{"pkg/hostlockdown"},
		forbidden: append([]string{"pkg/gvx/*", pkgSentryAll, "pkg/oci/*", "pkg/netbackend/*"}, runtimeOuterBans...),
	},
	{
		pkg:       "internal/lockdownprobe/cmd/lockdownprobe",
		tier:      Tier1Additive,
		allowed:   []string{"internal/lockdownprobe", "pkg/gvx", "pkg/hostlockdown", "pkg/netbackend", "pkg/tcpip/*", xSysUnix},
		forbidden: append([]string{pkgSentryAll, "pkg/oci/*"}, runtimeOuterBans...),
	},
	{
		pkg:             "internal/testelf",
		tier:            Tier1Additive,
		subtree:         true,
		forbidden:       []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
		forbiddenExcept: []string{"internal/testelf/*"},
	},
	{
		pkg:       "internal/testimage",
		tier:      Tier1Additive,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "internal/testdns",
		tier:      Tier1Additive,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "internal/benchreport",
		tier:      Tier1Additive,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "internal/pjdfsreport",
		tier:      Tier1Additive,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "scripts",
		tier:      Tier1Additive,
		subtree:   true,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "tools/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "tools/upstream",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"golang.org/x/mod/*", "tools/gostateify/stateify"},
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "tools/licenses",
		tier:      Tier1Additive,
		subtree:   true,
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "tools/gvisorlint",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"golang.org/x/tools/*", "tools/checklocks"},
		forbidden: []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "scripts/*", "runsc/*", "shim/*"},
	},
	{
		pkg:       "tools/androidprobe",
		tier:      Tier1Additive,
		subtree:   true,
		allowed:   []string{"internal/testelf", "pkg/abi/linux", xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:             "tools/gostateify",
		tier:            Tier1Additive,
		subtree:         true,
		allowed:         []string{"golang.org/x/tools/*"},
		forbidden:       []string{"pkg/*", "cmd/*", "internal/*", "e2e/*", "scripts/*", "runsc/*", "shim/*"},
		forbiddenExcept: []string{"pkg/state"},
		forbiddenProd:   []string{"pkg/state"},
		skipTrees:       []string{"tools/gostateify/internal/testfixture"},
	},
	{
		pkg:       "tools/gostateify/internal/testfixture",
		tier:      Tier1Additive,
		allowed:   []string{"pkg/state"},
		forbidden: lowLevelTier2Bans,
	},

	// Low-level foundation Tier 2 packages (must never import pkg/sentry/* or upper layers).
	{
		pkg:       "pkg/abi",
		tier:      Tier2Sibling,
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/abi/linux",
		tier:      Tier2Sibling,
		allowed:   []string{xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/aio",
		tier:      Tier2Sibling,
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:             "pkg/cpuid",
		tier:            Tier2Sibling,
		allowed:         []string{xSysWindows, xSysUnix},
		forbidden:       lowLevelTier2Bans,
		forbiddenExcept: []string{"pkg/sentry/platform/hvcommon"},
	},
	{
		pkg:       "pkg/erofs",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/errors/linuxerr", "pkg/log"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/fd",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/fdchannel",
		tier:      Tier2Sibling,
		allowed:   []string{xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/fdnotifier",
		tier:      Tier2Sibling,
		allowed:   []string{xSysUnix, "pkg/sync", "pkg/waiter"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/flipcall",
		tier:      Tier2Sibling,
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/hostarch",
		tier:      Tier2Sibling,
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/memutil",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/rawfile",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:            "pkg/ring0",
		tier:           Tier2Sibling,
		forbidden:      tier2UpperBans,
		forbiddenTier2: []string{pkgSentryAll},
	},
	{
		pkg:       "pkg/ring0/pagetables",
		tier:      Tier2Sibling,
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/safecopy",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/errors", "pkg/errors/linuxerr"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/sighandling",
		tier:      Tier2Sibling,
		allowed:   []string{xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/sync",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/syserr",
		tier:      Tier2Sibling,
		allowed:   []string{xSysUnix, "pkg/abi/linux/errno", "pkg/errors", "pkg/errors/linuxerr"},
		forbidden: lowLevelTier2Bans,
	},
	// Low-level Tier 3 safeguard keeping fsutil free of Sentry imports.
	{
		pkg:       "pkg/fsutil",
		tier:      Tier3Upstream,
		subtree:   true,
		allowed:   []string{xSysUnix},
		forbidden: lowLevelTier2Bans,
	},

	// Netstack Tier 2 packages (must never import pkg/sentry/* or upper layers).
	{
		pkg:       "pkg/tcpip",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/state", xSysWindows},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/tcpip/network/ipv4",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/state", "pkg/tcpip/*"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/tcpip/network/ipv6",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/tcpip/*"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/tcpip/stack",
		tier:      Tier2Sibling,
		allowed:   []string{"internal/weakmap", "pkg/atomicbitops", "pkg/log", "pkg/state", "pkg/sync", "pkg/tcpip/*"},
		forbidden: lowLevelTier2Bans,
	},
	{
		pkg:       "pkg/tcpip/transport/tcp",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/state", "pkg/tcpip/*", "pkg/waiter"},
		forbidden: lowLevelTier2Bans,
	},

	// Sentry Tier 2 packages.
	{
		pkg:       "pkg/sentry/arch",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/hostarch"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/devices/memdev",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/context", "pkg/errors/linuxerr", "pkg/sentry/kernel", "pkg/sentry/kernel/auth", "pkg/sentry/vfs", "pkg/sync", "pkg/usermem", "pkg/waiter"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:           "pkg/sentry/fsimpl/cgroup2fs",
		tier:          Tier2Sibling,
		allowed:       []string{"pkg/abi/linux", "pkg/atomicbitops", "pkg/context", "pkg/errors/linuxerr", "pkg/sentry/kernel", "pkg/sentry/usage", "pkg/sentry/vfs"},
		forbidden:     append([]string{xSysWindows}, append(slices.Clone(platformSiblings), tier2UpperBans...)...),
		forbiddenProd: []string{"pkg/sentry/platform/*"},
	},
	{
		pkg:           "pkg/sentry/fsimpl/erofs",
		tier:          Tier2Sibling,
		allowed:       []string{"pkg/abi/linux", "pkg/errors/linuxerr", "pkg/sentry/blockdev", "pkg/sentry/kernel/auth", "pkg/sentry/vfs"},
		forbidden:     append([]string{xSysWindows}, append(slices.Clone(platformSiblings), without(tier2UpperBans, "pkg/oci/*")...)...),
		forbiddenProd: []string{"pkg/sentry/platform/*", "pkg/oci/*"},
	},
	{
		pkg:       "pkg/sentry/fsimpl/iouringfs",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/errors/linuxerr"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/fsimpl/overlay",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/context", "pkg/sentry/uniqueid", "pkg/sentry/vfs", "pkg/state"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/fsimpl/proc",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/atomicbitops", "pkg/context", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/sentry/blockdev", "pkg/sentry/fsimpl/kernfs", "pkg/sentry/inet", "pkg/sentry/kernel", "pkg/sentry/kernel/auth", "pkg/sentry/socket/netstack", "pkg/sentry/vfs", "pkg/state", "pkg/sync", "pkg/tcpip/*", "pkg/usermem"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/fsimpl/sys",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/atomicbitops", "pkg/context", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/ipset", "pkg/sentry/blockdev", "pkg/sentry/fsimpl/kernfs", "pkg/sentry/inet", "pkg/sentry/kernel", "pkg/sentry/kernel/auth", "pkg/sentry/socket/netfilter", "pkg/sentry/socket/netstack", "pkg/sentry/vfs", "pkg/tcpip/*", "pkg/usermem"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/hostcpu",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/hostfd",
		tier:      Tier2Sibling,
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/kernel",
		tier:      Tier2Sibling,
		subtree:   true,
		allowed:   []string{"internal/weakmap", "pkg/abi/linux", "pkg/atomicbitops", "pkg/sentry/platform", "pkg/sentry/vfs", "pkg/state", "pkg/sync"},
		forbidden: append([]string{xSysWindows}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/kernel/shm",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/atomicbitops"},
		forbidden: append([]string{xSysWindows}, tier2UpperBans...),
	},
	{
		pkg:           "pkg/sentry/loader",
		tier:          Tier2Sibling,
		allowed:       []string{"pkg/context", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/sentry/mm"},
		forbidden:     append([]string{xSysWindows}, append(slices.Clone(platformSiblings), tier2UpperBans...)...),
		forbiddenProd: []string{"pkg/sentry/platform/*"},
	},
	{
		pkg:       "pkg/sentry/mm",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/context", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/safemem", "pkg/sentry/memmap", "pkg/sentry/pgalloc", "pkg/sentry/platform", "pkg/sentry/usage", "pkg/sentry/vfs", "pkg/state", "pkg/usermem"},
		forbidden: append([]string{xSysWindows}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/pgalloc",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix, "pkg/abi/linux", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/log", "pkg/memutil", "pkg/safemem", "pkg/sentry/memmap", "pkg/sentry/usage", "pkg/state", "pkg/sync"},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/platform",
		tier:      Tier2Sibling,
		allowed:   []string{xSysUnix, "pkg/context", "pkg/hostarch", "pkg/sentry/memmap"},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*"}, append(slices.Clone(platformSiblings), tier2UpperBans...)...),
	},
	{
		pkg:       "pkg/sentry/platform/platforms",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/sentry/platform/hvf", "pkg/sentry/platform/whpx"},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*"}, tier2UpperBans...),
	},
	{
		pkg:           "pkg/sentry/platform/systrap",
		tier:          Tier2Sibling,
		subtree:       true,
		allowed:       []string{"pkg/sentry/platform", "pkg/sentry/platform/hvcommon", "pkg/memutil", "pkg/abi/linux", "golang.org/x/arch/*"},
		forbidden:     append([]string{"pkg/sentry/kernel/*", "pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf"}, without(tier2UpperBans, "pkg/hostlockdown/*")...),
		forbiddenProd: []string{"pkg/hostlockdown/*"},
		// usertrap and rseqarea carry dedicated rules below.
		skipTrees: []string{"pkg/sentry/platform/systrap/usertrap", "pkg/sentry/platform/systrap/rseqarea"},
	},
	{
		pkg:       "pkg/sentry/platform/systrap/rseqarea",
		tier:      Tier1Additive,
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf"}, tier2UpperBans...),
	},
	{
		pkg:            "pkg/sentry/platform/systrap/usertrap",
		tier:           Tier2Sibling,
		subtree:        true,
		forbidden:      append([]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf"}, tier2UpperBans...),
		forbiddenTier2: []string{"pkg/sentry/kernel/*"},
	},
	{
		pkg:       "pkg/sentry/socket/netfilter",
		tier:      Tier2Sibling,
		allowed:   []string{"internal/weakmap", "pkg/abi/linux", "pkg/atomicbitops", "pkg/bits", "pkg/hostarch", "pkg/ipset", "pkg/log", "pkg/marshal", "pkg/marshal/primitive", "pkg/sentry/kernel", "pkg/state", "pkg/sync", "pkg/syserr", "pkg/tcpip/*"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/socket/netlink",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/context", "pkg/marshal/primitive", "pkg/sentry/socket/unix/transport", "pkg/sync", "pkg/syserr"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/socket/netlink/netfilter",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/context", "pkg/ipset", "pkg/log", "pkg/marshal/primitive", "pkg/sentry/kernel", "pkg/sentry/socket/netlink", "pkg/sentry/socket/netlink/nlmsg", "pkg/sentry/socket/netstack", "pkg/syserr", "pkg/tcpip/*"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/socket/netlink/route",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/context", "pkg/marshal/primitive", "pkg/sentry/inet", "pkg/sentry/socket/netlink", "pkg/sentry/socket/netlink/nlmsg", "pkg/sentry/socket/netstack", "pkg/syserr", "pkg/tcpip/*"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/socket/netstack",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/abi/linux/errno", "pkg/atomicbitops", "pkg/context", "pkg/errors", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/log", "pkg/marshal/primitive", "pkg/sentry/inet", "pkg/sentry/kernel", "pkg/sentry/kernel/auth", "pkg/sentry/socket/netlink/nlmsg", "pkg/state", "pkg/sync", "pkg/syserr", "pkg/tcpip/*"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/syscalls/linux",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/abi/linux", "pkg/errors/linuxerr", "pkg/hostarch", "pkg/sentry/arch", "pkg/sentry/kernel", "pkg/sentry/limits", "pkg/sentry/syscalls", "pkg/sentry/usage", "pkg/sentry/vfs", "pkg/waiter"},
		forbidden: append([]string{xSysWindows}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/time",
		tier:      Tier2Sibling,
		allowed:   []string{xSysWindows, xSysUnix},
		forbidden: append([]string{"pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/usage",
		tier:      Tier2Sibling,
		forbidden: append([]string{xSysWindows, "pkg/sentry/kernel/*", "pkg/sentry/vfs/*", "pkg/sentry/platform/*"}, tier2UpperBans...),
	},
	{
		pkg:       "pkg/sentry/vfs",
		tier:      Tier2Sibling,
		allowed:   []string{"pkg/state"},
		forbidden: append([]string{xSysWindows, "pkg/sentry/platform/*"}, tier2UpperBans...),
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

func tier2AllPackages() []string {
	var out []string
	for _, r := range boundaryRules {
		if r.tier == Tier2Sibling {
			out = append(out, r.pkg)
		}
	}
	return out
}

// sentryAPIUsers lists gvx-owned packages that implement or call Sentry interfaces.
var sentryAPIUsers = []string{
	"pkg/gvx",
	"pkg/sentry/fsimpl/hostfs",
	"pkg/sentry/fsimpl/ext4lite",
	"pkg/sentry/fsimpl/chunkcache",
	"pkg/sentry/fsimpl/fsutilx",
	"pkg/sentry/platform/whpx",
	"pkg/sentry/platform/hvf",
	"pkg/sentry/platform/hvcommon",
	"pkg/sentry/platform/systrap",
	"pkg/sentry/platform/systrap/usertrap",
}

var platformBackends = []string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/systrap"}

// boundaryExceptions lists dependencies forced by Go interface signatures outside the primary allowed column.
var boundaryExceptions = []importException{
	// Stateify autogenerated Tier 2 sibling files register savable types with pkg/state.
	{tier2AllPackages(), "pkg/state", "stateify code generation imports pkg/state in Tier 2 sibling packages"},
	// Sentry foundation packages appear in kernel, VFS, and platform method signatures.
	{sentryAPIUsers, "pkg/context", "Sentry entry points accept context.Context"},
	{sentryAPIUsers, "pkg/hostarch", "Sentry address and page types live in pkg/hostarch"},
	{sentryAPIUsers, "pkg/usermem", "guest memory I/O uses usermem.IO and usermem.IOOpts"},
	{sentryAPIUsers, "pkg/sentry/memmap", "platform and VFS memory mapping interfaces use memmap types"},
	{sentryAPIUsers, "pkg/errors/linuxerr", "VFS and kernel calls return linuxerr values"},
	{sentryAPIUsers, "pkg/fspath", "VFS path operations accept fspath.Path"},
	{sentryAPIUsers, "pkg/safemem", "VFS reads and writes use safemem block sequences"},
	{sentryAPIUsers, "pkg/atomicbitops", "dentry and option words use atomic upstream types"},
	{sentryAPIUsers, "pkg/log", "upstream logging package"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/systrap"}, "pkg/sentry/arch", "platform.Context.Switch exchanges arch.Context64 values"},
	{platformBackends, "pkg/sentry/platform/interrupt", "platform.Context.Switch callers wake a running vCPU via interrupt.Forwarder"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/hvcommon"}, "pkg/ring0/pagetables", "hardware backends build guest stage-1 and stage-2 page tables with pagetables"},
	{[]string{"pkg/sentry/platform/whpx"}, "pkg/cpuid", "amd64 whpx sizes the guest XSAVE layout from CPUID leaf 0xD"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/chunkcache", "pkg/sentry/fsimpl/fsutilx"}, "pkg/sentry/kernel/auth", "vfs.FilesystemImpl methods accept auth.Credentials"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/fsutilx"}, "pkg/sentry/limits", "VFS write paths read limits.FileSize"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite"}, "pkg/sentry/socket/unix/transport", "vfs.FilesystemImpl.BoundEndpointAt returns transport.BoundEndpoint"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite"}, "pkg/refs", "vfs.DentryImpl reference counting uses refs.RefCounter"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "golang.org/x/text/unicode/norm", "APFS stores names in NFD, requiring NFC conversion for guests"},
	{[]string{"pkg/sentry/fsimpl/ext4lite"}, "pkg/errors", "toLinuxErr extracts *errors.Error values returned by the engine"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/chunkcache"}, "pkg/sentry/kernel/pipe", "mknod FIFO files open via the VFS pipe implementation"},
	{[]string{"pkg/sentry/platform/systrap"}, "golang.org/x/sys/*", "Windows and macOS host memory and child stub APIs"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/time", "Windows fast-path spin windows read the cycle and performance counters"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/pgalloc", "16 KB host sub-block layer allocates composite pages from pgalloc"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/usage", "pgalloc.AllocOpts for a composite page requires usage.MemoryKind"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/seccomp/precompiledseccomp", "stubfilter_lookup_xplat.go builds Linux arm64 stub seccomp programs"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/platform/systrap/rseqarea", "Linux systrap siblings reference rseqarea layout definitions"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/platform/systrap/stubfilter", "Linux arm64 stub seccomp builder imports stubfilter"},
	{[]string{"pkg/sentry/kernel"}, "pkg/hostarch", "addrhole_xplat.go returns platform address holes as hostarch.AddrRange"},
	{[]string{"pkg/sentry/kernel"}, "pkg/errors/linuxerr", "kmsg_xplat.go returns EINVAL for /dev/kmsg writes above 1024 bytes"},
	{[]string{"pkg/sentry/kernel"}, "pkg/waiter", "kmsg_xplat.go wakes /dev/kmsg and syslog readers via waiter.Queue"},
	{[]string{"pkg/cpuid"}, "pkg/log", "arm64 feature discovery logs unrecognized CPU register fields"},
	{[]string{"pkg/cpuid"}, "pkg/sentry/platform/hvcommon", "windows arm64 reads guest MIDR_EL1 and ID register definitions from hvcommon"},

	// pkg/gvx boots the Sentry; kernel constructors require these types.
	{[]string{"pkg/gvx"}, "pkg/abi/linux", "Linux ABI constants for guest syscall numbers and errno values"},
	{[]string{"pkg/gvx"}, "pkg/cpuid", "kernel.Init requires a cpuid.FeatureSet"},
	{[]string{"pkg/gvx"}, "pkg/marshal/primitive", "guest memory copies use primitive marshal types"},
	{[]string{"pkg/gvx"}, "pkg/memutil", "kernel memory files require host memory views"},
	{[]string{"pkg/gvx"}, "pkg/waiter", "stdio file descriptions implement waiter.Waitable for blocking reads"},

	// pkg/netbackend: Netstack foundation packages live outside pkg/tcpip.
	{[]string{"pkg/netbackend"}, "pkg/buffer", "pkg/tcpip packets use pkg/buffer.Buffer values"},
	{[]string{"pkg/netbackend"}, "pkg/waiter", "pkg/tcpip endpoints signal readiness via pkg/waiter queues"},
	{[]string{"pkg/netbackend"}, "golang.zx2c4.com/wireguard/*", "Track B embeds wireguard-go for L3 tunnels"},
	{[]string{"pkg/netbackend"}, "golang.org/x/sys/*", "host DNS discovery reads Windows adapter addresses and macOS resolver state"},

	// pkg/gvx: Linux lockdown reuses the seccomp allowlist of the gVisor Sentry.
	{[]string{"pkg/gvx"}, "runsc/boot/filter/config", "Linux lockdown installs the seccomp allowlist from runsc"},
	{[]string{"pkg/gvx"}, "pkg/seccomp", "Linux lockdown compiles seccomp rules with upstream rule types"},
	{[]string{"pkg/gvx"}, "golang.org/x/sys/*", "Linux lockdown names syscalls and TTY bridges read terminal state"},

	// pkg/oci: EROFS writer and compression codecs.
	{[]string{"pkg/oci"}, "pkg/erofs", "OCI layer compiler writes images with the upstream erofs ABI"},
	{[]string{"pkg/oci"}, "pkg/fd", "Windows layer cache shares NT atomic rename primitives with pkg/fd"},
	{[]string{"pkg/oci"}, "github.com/klauspost/compress/*", "OCI puller decompresses zstd image layers"},
	{[]string{"pkg/oci"}, "github.com/cespare/xxhash/*", "layer cache computes xxhash digests for content addressing"},
	{[]string{"pkg/oci"}, "golang.org/x/sys/*", "Windows and Darwin layer caches open files with POSIX rename semantics"},
	{[]string{"cmd/rungv"}, "pkg/gvx/tuning", "CLI tune flags read and print the leaf tunable registry"},
	{[]string{"pkg/netbackend"}, "pkg/gvx/tuning", "leaf tunable registry supplies NAT, DNS, and forwarder defaults"},
}

// boundaryTestExceptions apply to _test.go files only.
var boundaryTestExceptions = []importException{
	{[]string{"internal/gvxshim"}, "github.com/containerd/containerd/v2/*", "interop tests exercise the pinned containerd lifecycle"},
	{[]string{"internal/gvxshim"}, "github.com/containerd/typeurl/v2", "interop tests marshal an OCI specification"},
	{[]string{"internal/gvxshim"}, "github.com/containerd/errdefs", "interop tests assert unsupported-operation errors"},
	{[]string{"internal/gvxshim"}, "github.com/opencontainers/runtime-spec/specs-go", "interop tests construct a minimal OCI specification"},
	{[]string{"pkg/gvx", "cmd/rungv"}, "internal/*", "tests load guest ELF, DNS, hypervisor, and image fixtures"},
	{[]string{"pkg/gvx", "e2e"}, "github.com/creack/pty", "darwin PTY tests verify host terminal raw mode restoration"},
	{[]string{"e2e"}, "pkg/gvx", "black-box suite boots sandboxes through the public SDK"},
	{[]string{"e2e"}, "pkg/gvx/tuning", "black-box suite configures tunable limits on sandboxes"},
	{[]string{"e2e"}, "pkg/oci", "black-box suite builds and caches local OCI images"},
	{[]string{"e2e"}, "pkg/netbackend", "black-box suite configures NAT and WireGuard backends"},
	{[]string{"e2e"}, "pkg/abi/linux", "black-box suite asserts Linux signal and errno constants"},
	{[]string{"e2e"}, "pkg/tcpip/*", "black-box suite constructs raw packets for netfilter and tunnel gates"},
	{[]string{"e2e"}, "pkg/sentry/fsimpl/hostfs", "M4 gate verifies hostfs metadata constants"},
	{[]string{"e2e"}, "internal/*", "black-box suite launches guest acceptance probes and ELF fixtures"},
	{[]string{"e2e"}, "golang.org/x/sys/unix/*", "Unix e2e tests configure non-blocking host descriptors and signals"},
	{[]string{"e2e"}, "golang.zx2c4.com/wireguard/*", "WireGuard e2e tests pair sandboxes with an in-memory peer"},
	{[]string{"pkg/sentry/platform/whpx", "pkg/sentry/platform/hvf", "pkg/sentry/platform/hvcommon"}, "golang.org/x/arch/*", "unit tests disassemble generated guest stubs"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/chunkcache", "pkg/sentry/fsimpl/cgroup2fs", "pkg/sentry/fsimpl/overlay", "pkg/sentry/socket/netlink/genetlink/wireguard"}, "pkg/sentry/pgalloc", "unit tests back mapped file chunks or kernel memory with pgalloc.MemoryFile"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/chunkcache", "pkg/sentry/fsimpl/cgroup2fs", "pkg/sentry/fsimpl/overlay", "pkg/sentry/socket/netlink/genetlink/wireguard"}, "pkg/memutil", "unit tests allocate backing memory for pgalloc.MemoryFile"},
	{[]string{"pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/chunkcache"}, "pkg/sentry/usage", "pgalloc.AllocOpts requires usage.MemoryKind"},
	{[]string{"pkg/sentry/devices/memdev", "pkg/sentry/fsimpl/cgroup2fs", "pkg/sentry/fsimpl/proc", "pkg/sentry/fsimpl/hostfs", "pkg/sentry/fsimpl/ext4lite", "pkg/sentry/fsimpl/sys"}, "pkg/sentry/uniqueid", "vfs.Init in unit tests requires uniqueid.Provider on context"},
	{[]string{"pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/kernel/auth", "cgroup2fs VFS unit tests pass auth.Credentials to OpenAt and MkdirAt"},
	{[]string{"pkg/sentry/fsimpl/cgroup2fs"}, "pkg/usermem", "cgroup2fs VFS unit tests read and write controller files via usermem"},
	{[]string{"pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/fsimpl/tmpfs", "cgroup2fs checkpoint tests mount tmpfs for a minimal init ELF"},
	{[]string{"pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/loader", "cgroup2fs checkpoint tests prepare VDSO for Kernel.CreateProcess"},
	{[]string{"pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/time", "cgroup2fs checkpoint tests initialize kernel Timekeeper clocks"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/errors", "unit tests compare errors.Error values returned by VFS"},
	{[]string{"pkg/sentry/platform/hvf", "pkg/sentry/platform/systrap", "pkg/sentry/arch", "pkg/sentry/loader", "pkg/sentry/fsimpl/cgroup2fs"}, "pkg/cpuid", "unit tests initialize CPUID feature sets before constructing contexts"},
	{[]string{"pkg/sentry/platform/systrap", "pkg/sentry/platform/hvf"}, "pkg/sentry/pgalloc", "unit tests allocate pgalloc.MemoryFile for guest pages"},
	{[]string{"pkg/sentry/platform/systrap", "pkg/sentry/platform/hvf"}, "pkg/sentry/usage", "pgalloc.AllocOpts requires usage.MemoryKind"},
	{[]string{"pkg/hostlockdown"}, "pkg/seccomp", "Linux lockdown tests install a seccomp filter via Options.InstallSyscallFilter"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/hostlockdown", "Windows lockdown test verifies stub execution after hostlockdown.Apply"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/hostlockdown", "Darwin watcher test verifies hostfs operation after hostlockdown.Apply"},
	{[]string{"pkg/sentry/fsimpl/hostfs"}, "pkg/waiter", "FIFO unit test blocks inside VFS via waiter.Queue"},
	{[]string{"pkg/sentry/platform/systrap"}, "pkg/sentry/loader/vdsodata", "vDSO test verifies that the mapped image omits x18"},
	{[]string{"pkg/sentry/arch", "pkg/sentry/socket/netlink"}, "pkg/usermem", "unit tests read and write guest structures through usermem"},
	{[]string{"pkg/sentry/devices/memdev", "pkg/sentry/fsimpl/cgroup2fs", "pkg/sentry/fsimpl/overlay", "pkg/sentry/fsimpl/proc", "pkg/sentry/fsimpl/sys"}, "pkg/sentry/ktime", "unit tests supply a synthetic clock to filesystem contexts"},
	{[]string{"pkg/sentry/fsimpl/erofs", "pkg/sentry/fsimpl/cgroup2fs"}, "pkg/hostarch", "unit tests align pages and user address ranges with hostarch constants"},
	{[]string{"pkg/sentry/fsimpl/erofs", "pkg/sentry/loader", "pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/memmap", "unit tests construct or exercise memmap mappable implementations"},
	{[]string{"pkg/sentry/fsimpl/cgroup2fs", "pkg/sentry/fsimpl/overlay", "pkg/sentry/fsimpl/proc", "pkg/sentry/fsimpl/sys"}, "pkg/fspath", "VFS unit tests parse virtual paths with fspath.Parse"},
	{[]string{"pkg/sentry/fsimpl/overlay"}, "pkg/sentry/fsimpl/tmpfs", "overlay save and restore tests mount tmpfs layers"},
	{[]string{"pkg/sentry/devices/memdev", "pkg/sentry/fsimpl/cgroup2fs", "pkg/sentry/fsimpl/proc", "pkg/sentry/fsimpl/sys", "pkg/sentry/mm", "pkg/sentry/loader"}, "pkg/sentry/limits", "unit tests attach a limits.LimitSet to test contexts"},
	{[]string{"pkg/sentry/fsimpl/sys"}, "pkg/syserr", "sysfs unit tests compare syserr error codes"},
	{[]string{"pkg/sentry/mm", "pkg/sentry/loader", "pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/arch", "unit tests construct arch.Context64 address spaces or syscall tables"},
	{[]string{"pkg/sentry/loader", "pkg/sentry/fsimpl/cgroup2fs"}, "pkg/abi", "unit tests pass abi.Linux to arch or syscall table registration"},
	{[]string{"pkg/sentry/loader"}, "pkg/abi/linux", "loader tests construct ELF program headers with Linux ABI constants"},
	{[]string{"pkg/sentry/fsimpl/overlay", "pkg/sentry/loader"}, "pkg/sentry/kernel/auth", "unit tests supply auth.NewRootCredentials to VFS"},
	{[]string{"pkg/sentry/loader", "pkg/sentry/fsimpl/cgroup2fs"}, "pkg/sentry/platform", "unit tests provide a minimal platform.Platform stub"},
	{[]string{"pkg/sentry/loader"}, "pkg/sentry/vfs", "loader tests map synthetic ELF segments from an anonymous VFS file"},
	{[]string{"pkg/sentry/socket/netfilter", "pkg/sentry/socket/netstack", "pkg/tcpip/network/ipv4", "pkg/tcpip/network/ipv6", "pkg/tcpip/stack"}, "pkg/buffer", "packet unit tests construct payloads with pkg/buffer"},
	{[]string{"pkg/sentry/socket/netstack", "pkg/tcpip/network/ipv4", "pkg/tcpip/network/ipv6", "pkg/tcpip/stack"}, "pkg/waiter", "socket and stack tests register readiness waiters"},
	{[]string{"pkg/sentry/socket/netlink"}, "pkg/abi/linux/errno", "netlink unit tests assert Linux errno constants"},
	{[]string{"pkg/sentry/socket/netlink"}, "pkg/errors/linuxerr", "netlink unit tests compare linuxerr return values"},
	{[]string{"pkg/sentry/socket/netlink"}, "pkg/sentry/socket/unix", "netlink unit tests pair endpoints with unix sockets"},
	{[]string{"pkg/sentry/socket/netfilter", "pkg/tcpip/transport/tcp", "tools/gostateify"}, "pkg/state", "stateify round-trip unit tests serialize and restore structs with pkg/state"},
	{[]string{"pkg/sentry/pgalloc"}, "pkg/sentry/state/stateio", "save and restore unit tests construct stateio async page streams"},
	{[]string{"pkg/sentry/pgalloc"}, "pkg/compressio", "save and restore unit tests round-trip streams through compressio"},
	{[]string{"pkg/gvx"}, "pkg/state", "EROFS restore tests round-trip VFS mounts and open file descriptions"},
}

func exceptionApplies(ex importException, pkg, imp string) bool {
	return slices.Contains(ex.pkgs, pkg) && matchImportPattern(ex.prefix, imp)
}

// BoundaryViolation describes one import or literal that crosses an architectural boundary.
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

// normalizeImport strips module prefixes and maps embedded unix paths to their canonical form.
func normalizeImport(impPath string) string {
	trimmed := strings.TrimPrefix(impPath, modulePrefix)
	trimmed = strings.TrimPrefix(trimmed, legacyModulePrefix)
	if trimmed == "internal/xsys/unix" {
		return "golang.org/x/sys/unix"
	}
	return trimmed
}

func isStdlibImport(impPath string) bool {
	first, _, _ := strings.Cut(impPath, "/")
	return !strings.Contains(first, ".")
}

// matchImportPattern reports whether imp matches pattern.
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

func ruleAppliesToDir(rule importRule, pkgDir string) bool {
	if slices.ContainsFunc(rule.skipTrees, func(tree string) bool { return inTree(pkgDir, tree) }) {
		return false
	}
	if rule.subtree {
		return inTree(pkgDir, rule.pkg)
	}
	return pkgDir == rule.pkg
}

func hasCoveringRule(pkgDir string, tier IsolationTier) bool {
	for _, rule := range boundaryRules {
		switch tier {
		case Tier1Additive:
			if rule.tier == Tier1Additive && ruleAppliesToDir(rule, pkgDir) {
				return true
			}
		case Tier2Sibling:
			if rule.tier == Tier2Sibling && rule.pkg == pkgDir {
				return true
			}
		}
	}
	return false
}

func dirNeedsASTBody(pkgDir string) bool {
	for _, rule := range boundaryRules {
		if ruleAppliesToDir(rule, pkgDir) && len(rule.forbiddenLiterals) > 0 {
			return true
		}
	}
	return false
}

// verifyGlobalBoundaries enforces cross-repository invariants independent of per-package rules.
func verifyGlobalBoundaries(relSlash, pkgDir string, tier IsolationTier, impPath string) (BoundaryViolation, bool) {
	if isStdlibImport(impPath) || impPath == "C" {
		return BoundaryViolation{}, false
	}
	imp := normalizeImport(impPath)
	if !inTree(pkgDir, "e2e") && matchImportPattern("e2e/*", imp) {
		return BoundaryViolation{File: relSlash, Import: impPath, Package: pkgDir, Reason: "package must never import e2e suite"}, true
	}
	if !inTree(pkgDir, "scripts") && matchImportPattern("scripts/*", imp) {
		return BoundaryViolation{File: relSlash, Import: impPath, Package: pkgDir, Reason: "package must never import scripts tree"}, true
	}
	if inTree(pkgDir, "pkg") {
		if pattern, bad := matchAny([]string{"cmd/*", "tools/*", "internal/gvxshim/*"}, imp); bad {
			return BoundaryViolation{File: relSlash, Import: impPath, Package: pkgDir, Reason: "runtime pkg tree must never import " + pattern}, true
		}
	}
	if tier == Tier2Sibling && !isTestFile(relSlash) {
		if pattern, bad := matchAny(tier2UpperBans, imp); bad {
			return BoundaryViolation{File: relSlash, Import: impPath, Package: pkgDir, Reason: "Tier 2 sibling file must never import " + pattern}, true
		}
	}
	return BoundaryViolation{}, false
}

// validateFileImports verifies the imports and string literals of one parsed file.
func validateFileImports(relSlash string, tier IsolationTier, file *ast.File) []BoundaryViolation {
	pkgDir := path.Dir(relSlash)
	var out []BoundaryViolation
	var matchedRule bool

	for _, rule := range boundaryRules {
		if !ruleAppliesToDir(rule, pkgDir) {
			continue
		}
		matchedRule = true
		for _, spec := range file.Imports {
			impPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				out = append(out, BoundaryViolation{File: relSlash, Import: spec.Path.Value, Package: rule.pkg, Reason: "unquotable import path"})
				continue
			}
			if v, bad := validateOneImport(relSlash, pkgDir, tier, rule, impPath); bad {
				out = append(out, v)
			}
		}
		if len(rule.forbiddenLiterals) > 0 {
			out = append(out, validateLiterals(relSlash, rule, file)...)
		}
	}

	if !matchedRule {
		for _, spec := range file.Imports {
			impPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				out = append(out, BoundaryViolation{File: relSlash, Import: spec.Path.Value, Package: pkgDir, Reason: "unquotable import path"})
				continue
			}
			if v, bad := verifyGlobalBoundaries(relSlash, pkgDir, tier, impPath); bad {
				out = append(out, v)
			}
		}
	}
	return out
}

func validateOneImport(relSlash, pkgDir string, tier IsolationTier, rule importRule, impPath string) (BoundaryViolation, bool) {
	if isStdlibImport(impPath) || impPath == "C" {
		return BoundaryViolation{}, false
	}
	imp := normalizeImport(impPath)
	if pattern, bad := matchAny(rule.forbidden, imp); bad {
		if _, exempt := matchAny(rule.forbiddenExcept, imp); !exempt {
			return BoundaryViolation{File: relSlash, Import: impPath, Package: rule.pkg, Reason: "forbidden by SPEC 2.1 (" + pattern + ")"}, true
		}
	}
	if !isTestFile(relSlash) {
		if pattern, bad := matchAny(rule.forbiddenProd, imp); bad {
			return BoundaryViolation{File: relSlash, Import: impPath, Package: rule.pkg, Reason: "forbidden in production code (" + pattern + ")"}, true
		}
	}
	if tier == Tier2Sibling {
		if pattern, bad := matchAny(rule.forbiddenTier2, imp); bad {
			return BoundaryViolation{File: relSlash, Import: impPath, Package: rule.pkg, Reason: "forbidden in Tier 2 sibling file (" + pattern + ")"}, true
		}
	}
	if v, bad := verifyGlobalBoundaries(relSlash, pkgDir, tier, impPath); bad {
		return v, true
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
	for _, ex := range boundaryExceptions {
		if exceptionApplies(ex, rule.pkg, imp) {
			return BoundaryViolation{}, false
		}
	}
	if isTestFile(relSlash) {
		for _, ex := range boundaryTestExceptions {
			if exceptionApplies(ex, rule.pkg, imp) {
				return BoundaryViolation{}, false
			}
		}
	}
	return BoundaryViolation{File: relSlash, Import: impPath, Package: rule.pkg, Reason: "not in the SPEC 2.1 allowed list and not a registered exception"}, true
}

func validateLiterals(relSlash string, rule importRule, file *ast.File) []BoundaryViolation {
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
// Upstream Tier 3 files that skip every non-Linux Priority-0 target stay outside
// Windows and macOS builds, so their host imports do not violate Sentry boundaries.
func auditFileImports(fset *token.FileSet, absPath, relSlash string, tier IsolationTier) ([]BoundaryViolation, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", relSlash, err)
	}
	return auditSourceImports(fset, absPath, relSlash, tier, src)
}

func auditSourceImports(fset *token.FileSet, absPath, relSlash string, tier IsolationTier, src []byte) ([]BoundaryViolation, error) {
	violations, _, err := parseAndAuditSource(fset, absPath, relSlash, tier, src)
	return violations, err
}

func parseAndAuditSource(fset *token.FileSet, absPath, relSlash string, tier IsolationTier, src []byte) ([]BoundaryViolation, int, error) {
	mode := parser.ImportsOnly
	if dirNeedsASTBody(path.Dir(relSlash)) {
		mode = 0
	}
	file, err := parser.ParseFile(fset, absPath, src, mode)
	if err != nil {
		return nil, 0, fmt.Errorf("parse imports in %s: %w", relSlash, err)
	}
	pkgEnd := len(src)
	if tf := fset.File(file.Name.End()); tf != nil && file.Name.End().IsValid() {
		if off := tf.Offset(file.Name.End()); off > 0 && off < len(src) {
			pkgEnd = off
		}
	}
	violations := validateFileImports(relSlash, tier, file)
	if len(violations) == 0 || tier != Tier3Upstream {
		return violations, pkgEnd, nil
	}
	set, err := buildSet(path.Base(relSlash), src, nonLinuxTargets)
	if err != nil {
		return nil, pkgEnd, err
	}
	if !anyTrue(set) {
		return nil, pkgEnd, nil
	}
	return violations, pkgEnd, nil
}

type discoveredPkg struct {
	activeOnTargets bool
	hasTier1        bool
	hasTier2Prod    bool
	hasTier3        bool
}

// isAdditiveTopLevelTree reports whether pkgDir sits inside a gvx-only top-level tree
// outside upstream/go even without an upstream archive.
func isAdditiveTopLevelTree(pkgDir string) bool {
	return inTree(pkgDir, "cmd") || inTree(pkgDir, "e2e") || inTree(pkgDir, "scripts") || inTree(pkgDir, "internal")
}

func hasOSArchFilenameSuffix(stem string) bool {
	if _, last, ok := strings.Cut(stem, "_"); ok {
		if idx := strings.LastIndexByte(last, '_'); idx >= 0 {
			last = last[idx+1:]
		}
		return knownGOOS[last] || knownGOARCH[last] || last == "unix"
	}
	return false
}

// matchesAnyTarget reports whether any of the five target platforms compiles name.
func matchesAnyTarget(name string, header []byte) (bool, error) {
	if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
		return false, nil
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(name, ".go"), "_test")
	if !hasOSArchFilenameSuffix(stem) && !bytes.Contains(header, []byte("go:build")) && !bytes.Contains(header, []byte("+build")) {
		return true, nil
	}
	snippet := make([]byte, len(header)+1)
	copy(snippet, header)
	snippet[len(header)] = '\n'

	hasCgo := bytes.Contains(header, []byte("cgo"))
	for _, t := range allTargets {
		cgoModes := []bool{false}
		if hasCgo {
			cgoModes = []bool{false, true}
		}
		for _, cgoEnabled := range cgoModes {
			ctx := build.Context{
				GOOS:        t.goos,
				GOARCH:      t.goarch,
				CgoEnabled:  cgoEnabled,
				Compiler:    "gc",
				ReleaseTags: build.Default.ReleaseTags,
				OpenFile: func(string) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(snippet)), nil
				},
			}
			ok, err := ctx.MatchFile("/virtual", name)
			if err != nil {
				return false, fmt.Errorf("match build constraints of %s for %s/%s: %w", name, t.goos, t.goarch, err)
			}
			if ok {
				return true, nil
			}
		}
	}
	return false, nil
}

type boundaryFileJob struct {
	abs       string
	relSlash  string
	submodule bool
}

type boundaryFileResult struct {
	violations    []BoundaryViolation
	matchedTarget bool
	tier          IsolationTier
	err           error
}

// VerifyBoundaries discovers every root-module Go package across all five target platforms.
// It enforces fail-closed rule coverage on Tier 1 and Tier 2 packages and validates imports in memory.
func VerifyBoundaries(cfg BoundaryConfig) (BoundaryReport, error) {
	rootDir := cfg.RootDir
	if rootDir == "" {
		rootDir = "."
	}

	var upstreamDirs map[string]bool
	if cfg.Upstream != nil {
		upstreamDirs = make(map[string]bool, len(cfg.Upstream.Files)/4)
		for rel := range cfg.Upstream.Files {
			upstreamDirs[path.Dir(rel)] = true
		}
	}

	var jobs []boundaryFileJob
	var report BoundaryReport

	walkErr := filepath.WalkDir(rootDir, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(rootDir, abs)
		if err != nil {
			return fmt.Errorf("rel path %s: %w", abs, err)
		}
		relSlash := filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".agents", "vendor", "third_party", "testdata":
				return filepath.SkipDir
			}
			if relSlash == "upstream" || relSlash == ".upstream" {
				return filepath.SkipDir
			}
			if relSlash != "." {
				if _, statErr := os.Stat(filepath.Join(abs, "go.mod")); statErr == nil {
					if relSlash == "tools/shiminterop" {
						return collectSubmoduleJobs(abs, relSlash, &jobs)
					}
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(relSlash, ".go") {
			return nil
		}
		jobs = append(jobs, boundaryFileJob{abs: abs, relSlash: relSlash})
		return nil
	})
	if walkErr != nil {
		return report, walkErr
	}

	report.VerifiedFiles = len(jobs)
	results := make([]boundaryFileResult, len(jobs))
	workers := min(max(runtime.GOMAXPROCS(0), 1), 16, max(len(jobs), 1))
	var nextIdx atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				idx := int(nextIdx.Add(1) - 1)
				if idx >= len(jobs) {
					return
				}
				results[idx] = verifyOneBoundaryJob(token.NewFileSet(), jobs[idx])
			}
		})
	}
	wg.Wait()

	pkgs := make(map[string]*discoveredPkg)
	var errs []error
	for i, job := range jobs {
		res := results[i]
		if res.err != nil {
			return report, res.err
		}
		for _, v := range res.violations {
			errs = append(errs, v)
		}
		if job.submodule || !res.matchedTarget {
			continue
		}
		pkgDir := path.Dir(job.relSlash)
		p, ok := pkgs[pkgDir]
		if !ok {
			p = &discoveredPkg{}
			pkgs[pkgDir] = p
		}
		p.activeOnTargets = true
		switch res.tier {
		case Tier1Additive:
			p.hasTier1 = true
		case Tier2Sibling:
			if !isTestFile(job.relSlash) {
				p.hasTier2Prod = true
			}
		case Tier3Upstream:
			p.hasTier3 = true
		}
	}

	dirs := make([]string, 0, len(pkgs))
	for dir := range pkgs {
		dirs = append(dirs, dir)
	}
	slices.Sort(dirs)

	for _, dir := range dirs {
		p := pkgs[dir]
		if !p.activeOnTargets {
			continue
		}
		var isTier1 bool
		if upstreamDirs != nil {
			isTier1 = p.hasTier1 || !upstreamDirs[dir]
		} else {
			isTier1 = p.hasTier1 || isAdditiveTopLevelTree(dir) || !p.hasTier3
		}
		switch {
		case isTier1:
			report.Tier1Packages = append(report.Tier1Packages, dir)
			if !hasCoveringRule(dir, Tier1Additive) {
				errs = append(errs, UncoveredPackageError{Package: dir, Tier: Tier1Additive})
			}
		case p.hasTier2Prod:
			report.Tier2Packages = append(report.Tier2Packages, dir)
			if !hasCoveringRule(dir, Tier2Sibling) {
				errs = append(errs, UncoveredPackageError{Package: dir, Tier: Tier2Sibling})
			}
		}
	}

	return report, errors.Join(errs...)
}

func verifyOneBoundaryJob(fset *token.FileSet, job boundaryFileJob) boundaryFileResult {
	src, err := os.ReadFile(job.abs)
	if err != nil {
		return boundaryFileResult{err: fmt.Errorf("read %s: %w", job.relSlash, err)}
	}
	tier := Tier1Additive
	if !job.submodule {
		tier = ClassifyFile(job.relSlash)
	}
	vs, pkgEnd, err := parseAndAuditSource(fset, job.abs, job.relSlash, tier, src)
	if err != nil {
		return boundaryFileResult{err: err}
	}
	if job.submodule {
		return boundaryFileResult{violations: vs, tier: tier}
	}
	matched, err := matchesAnyTarget(path.Base(job.relSlash), src[:pkgEnd])
	if err != nil {
		return boundaryFileResult{err: err}
	}
	return boundaryFileResult{violations: vs, matchedTarget: matched, tier: tier}
}

// collectSubmoduleJobs queues Go files inside tools/shiminterop for SPEC 2.1 verification
// while excluding the isolated module from root-module discovery.
func collectSubmoduleJobs(subRoot, subRel string, jobs *[]boundaryFileJob) error {
	err := filepath.WalkDir(subRoot, func(abs string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(subRoot, abs)
		if relErr != nil {
			return relErr
		}
		*jobs = append(*jobs, boundaryFileJob{
			abs:       abs,
			relSlash:  subRel + "/" + filepath.ToSlash(rel),
			submodule: true,
		})
		return nil
	})
	if err != nil {
		return err
	}
	return filepath.SkipDir
}
