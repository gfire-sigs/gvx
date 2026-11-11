// Package stateify generates reflection-free pkg/state methods for Go packages.
package stateify

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"go/build/constraint"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// PackageTier classifies a package directory under the repository isolation rules.
type PackageTier int

const (
	// PackageTierShared identifies a package shared with upstream (Tier 2 and Tier 3 files).
	PackageTierShared PackageTier = iota
	// PackageTier1 identifies an additive package owned exclusively by gvx.
	PackageTier1
)

// PartitionKind names one generated state autogen output partition inside a package.
type PartitionKind string

const (
	PartitionDefault PartitionKind = "default"
	PartitionUnsafe  PartitionKind = "unsafe"
	PartitionXplat   PartitionKind = "xplat"
	PartitionDarwin  PartitionKind = "darwin"
	PartitionWindows PartitionKind = "windows"
	PartitionLinux   PartitionKind = "linux"
)

var partitionOrder = []PartitionKind{
	PartitionDefault,
	PartitionUnsafe,
	PartitionXplat,
	PartitionDarwin,
	PartitionWindows,
	PartitionLinux,
}

// tier1Prefixes matches the additive package prefixes in tools/upstream/diff_audit.go.
var tier1Prefixes = []string{
	"cmd/rungv/",
	"cmd/containerd-shim-gvx-v2/",
	"pkg/gvx/",
	"pkg/oci/",
	"pkg/netbackend/",
	"pkg/hostlockdown/",
	"pkg/sentry/blockdev/",
	"pkg/sentry/platform/whpx/",
	"pkg/sentry/platform/hvf/",
	"pkg/sentry/fsimpl/hostfs/",
	"pkg/sentry/fsimpl/ext4lite/",
	"pkg/sentry/fsimpl/chunkcache/",
	"pkg/sentry/fsimpl/fsutilx/",
	"pkg/sentry/socket/netlink/genetlink/",
	"pkg/ipset/",
	"pkg/tcpip/link/vxlan/",
	"pkg/tcpip/link/wgtun/",
	"pkg/sentry/platform/hvcommon/",
	"e2e/",
	"scripts/",
	"tools/upstream/",
	"tools/shiminterop/",
	"tools/licenses/",
	"tools/gvisorlint/",
	"tools/androidprobe/",
	"tools/gostateify/",
	"android/",
	"docs/",
	"internal/",
}

// Tier1Prefixes returns a copy of the additive package directory prefixes.
func Tier1Prefixes() []string {
	return slices.Clone(tier1Prefixes)
}

// ClassifyPackage returns PackageTier1 when relPkgDir falls under an additive prefix.
func ClassifyPackage(relPkgDir string) PackageTier {
	clean := strings.TrimPrefix(filepath.ToSlash(relPkgDir), "./")
	if clean != "" && !strings.HasSuffix(clean, "/") {
		clean += "/"
	}
	for _, prefix := range tier1Prefixes {
		if strings.HasPrefix(clean, prefix) {
			return PackageTier1
		}
	}
	return PackageTierShared
}

// ClassifyFilePartition assigns a non-autogen, non-test Go file to an output partition.
func ClassifyFilePartition(pkgTier PackageTier, baseName string, partitionByTier bool) PartitionKind {
	return classifyFilePartition(pkgTier, baseName, partitionByTier, false)
}

func classifyFilePartition(pkgTier PackageTier, baseName string, partitionByTier, tier1MergeXplat bool) PartitionKind {
	if !partitionByTier {
		return PartitionDefault
	}
	switch {
	case hasUnderscoreToken(baseName, "darwin"):
		return PartitionDarwin
	case hasUnderscoreToken(baseName, "windows"):
		return PartitionWindows
	case !tier1MergeXplat && hasUnderscoreToken(baseName, "xplat"):
		return PartitionXplat
	case pkgTier == PackageTier1 && hasUnderscoreToken(baseName, "linux"):
		return PartitionLinux
	case pkgTier == PackageTierShared && isUpstreamUnsafeSource(baseName):
		return PartitionUnsafe
	default:
		return PartitionDefault
	}
}

func isUpstreamUnsafeSource(baseName string) bool {
	return strings.HasSuffix(baseName, "_unsafe.go") && !strings.HasSuffix(baseName, "_abi_autogen_unsafe.go")
}

func hasUnderscoreToken(baseName, target string) bool {
	stem := strings.TrimSuffix(baseName, path.Ext(baseName))
	for tok := range strings.SplitSeq(stem, "_") {
		if tok == target {
			return true
		}
	}
	return false
}

func isTier3Partition(kind PartitionKind) bool {
	return kind == PartitionDefault || kind == PartitionUnsafe
}

func isSiblingPartition(kind PartitionKind) bool {
	switch kind {
	case PartitionXplat, PartitionDarwin, PartitionWindows, PartitionLinux:
		return true
	default:
		return false
	}
}

// partitionCanSupply reports whether declarations in providerPart may supply
// localTypes, receivers, or hooks to targetPart when providerConstraint covers targetConstraint.
func partitionCanSupply(pkgTier PackageTier, providerPart, targetPart PartitionKind) bool {
	if providerPart == targetPart {
		return true
	}
	if pkgTier == PackageTierShared && isTier3Partition(targetPart) {
		// Tier 2 sibling partitions must never mutate Tier 3 output partitions.
		return isTier3Partition(providerPart)
	}
	if isTier3Partition(providerPart) || providerPart == PartitionXplat {
		return true
	}
	return false
}

// CanonicalPartitionConstraint returns the primary build constraint for a partition kind.
func CanonicalPartitionConstraint(kind PartitionKind) constraint.Expr {
	switch kind {
	case PartitionWindows:
		return &constraint.TagExpr{Tag: "windows"}
	case PartitionDarwin:
		return &constraint.TagExpr{Tag: "darwin"}
	case PartitionLinux:
		return &constraint.TagExpr{Tag: "linux"}
	default:
		return nil
	}
}

// OutputFileName returns the canonical generated filename for a package name and partition.
func OutputFileName(pkgName string, kind PartitionKind) string {
	switch kind {
	case PartitionUnsafe:
		return pkgName + "_unsafe_state_autogen.go"
	case PartitionXplat:
		return pkgName + "_xplat_state_autogen.go"
	case PartitionDarwin:
		return pkgName + "_darwin_state_autogen.go"
	case PartitionWindows:
		return pkgName + "_windows_state_autogen.go"
	case PartitionLinux:
		return pkgName + "_linux_state_autogen.go"
	default:
		return pkgName + "_state_autogen.go"
	}
}

// SubPartitionOutputFileName returns the generated filename for (kind, expr).
// Groups matching CanonicalPartitionConstraint(kind) use the canonical filename;
// non-equivalent build constraints receive a deterministic suffixed filename.
func SubPartitionOutputFileName(pkgName string, kind PartitionKind, expr constraint.Expr) string {
	if EquivalentConstraints(expr, CanonicalPartitionConstraint(kind)) {
		return OutputFileName(pkgName, kind)
	}
	slug := constraintFileSlug(kind, expr)
	switch kind {
	case PartitionUnsafe:
		return pkgName + "_unsafe_" + slug + "_state_autogen.go"
	case PartitionXplat:
		return pkgName + "_xplat_" + slug + "_state_autogen.go"
	case PartitionDarwin:
		return pkgName + "_darwin_" + slug + "_state_autogen.go"
	case PartitionWindows:
		return pkgName + "_windows_" + slug + "_state_autogen.go"
	case PartitionLinux:
		return pkgName + "_linux_" + slug + "_state_autogen.go"
	default:
		return pkgName + "_" + slug + "_state_autogen.go"
	}
}

func constraintFileSlug(kind PartitionKind, expr constraint.Expr) string {
	if expr == nil {
		return "unconstrained"
	}
	var stripOSTag string
	switch kind {
	case PartitionWindows:
		stripOSTag = "windows"
	case PartitionDarwin:
		stripOSTag = "darwin"
	case PartitionLinux:
		stripOSTag = "linux"
	}
	trimmed := expr
	if stripOSTag != "" {
		terms := flattenAnd(expr)
		kept := make([]constraint.Expr, 0, len(terms))
		for _, term := range terms {
			if tag, ok := term.(*constraint.TagExpr); ok && tag.Tag == stripOSTag {
				continue
			}
			kept = append(kept, term)
		}
		if len(kept) > 0 {
			trimmed = kept[0]
			for _, next := range kept[1:] {
				trimmed = &constraint.AndExpr{X: trimmed, Y: next}
			}
		}
	}
	slug := exprToSlug(trimmed)
	if slug == "" {
		return "constrained"
	}
	return slug
}

func exprToSlug(expr constraint.Expr) string {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		return sanitizeSlugToken(e.Tag)
	case *constraint.NotExpr:
		return "not_" + exprToSlug(e.X)
	case *constraint.OrExpr:
		parts := flattenOr(e)
		slugs := make([]string, len(parts))
		for i, p := range parts {
			slugs[i] = exprToSlug(p)
		}
		slices.Sort(slugs)
		return strings.Join(slices.Compact(slugs), "_")
	case *constraint.AndExpr:
		parts := flattenAnd(e)
		type rankedSlug struct {
			rank int
			slug string
		}
		ranked := make([]rankedSlug, len(parts))
		for i, p := range parts {
			s := exprToSlug(p)
			r := 2
			if tag, ok := p.(*constraint.TagExpr); ok {
				if knownGOOS[tag.Tag] {
					r = 0
				} else if knownGOARCH[tag.Tag] {
					r = 1
				}
			}
			ranked[i] = rankedSlug{rank: r, slug: s}
		}
		slices.SortFunc(ranked, func(a, b rankedSlug) int {
			if c := cmp.Compare(a.rank, b.rank); c != 0 {
				return c
			}
			return cmp.Compare(a.slug, b.slug)
		})
		out := make([]string, len(ranked))
		for i, rs := range ranked {
			out[i] = rs.slug
		}
		return strings.Join(slices.Compact(out), "_")
	default:
		return sanitizeSlugToken(expr.String())
	}
}

func sanitizeSlugToken(raw string) string {
	var sb strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else if r >= 'A' && r <= 'Z' {
			sb.WriteRune(r + ('a' - 'A'))
		} else {
			sb.WriteByte('_')
		}
	}
	return strings.Trim(sb.String(), "_")
}

// knownGOOS lists Go target operating system tokens recognized in *_GOOS.go filenames.
var knownGOOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"js":        true,
	"linux":     true,
	"nacl":      true,
	"netbsd":    true,
	"openbsd":   true,
	"plan9":     true,
	"solaris":   true,
	"unix":      true,
	"wasip1":    true,
	"windows":   true,
	"zos":       true,
}

var unixGOOS = map[string]bool{
	"aix":       true,
	"android":   true,
	"darwin":    true,
	"dragonfly": true,
	"freebsd":   true,
	"hurd":      true,
	"illumos":   true,
	"ios":       true,
	"linux":     true,
	"netbsd":    true,
	"openbsd":   true,
	"solaris":   true,
}

// knownGOARCH lists Go target architecture tokens recognized in *_GOARCH.go filenames.
var knownGOARCH = map[string]bool{
	"386":         true,
	"amd64":       true,
	"amd64p32":    true,
	"arm":         true,
	"arm64":       true,
	"arm64be":     true,
	"armbe":       true,
	"loong64":     true,
	"mips":        true,
	"mips64":      true,
	"mips64le":    true,
	"mips64p32":   true,
	"mips64p32le": true,
	"mipsle":      true,
	"ppc":         true,
	"ppc64":       true,
	"ppc64le":     true,
	"riscv":       true,
	"riscv64":     true,
	"s390":        true,
	"s390x":       true,
	"sparc":       true,
	"sparc64":     true,
	"wasm":        true,
}

// ExtractFileConstraint returns the combined explicit and filename build constraint for a Go file.
// It returns nil when the file builds without platform or tag restrictions.
func ExtractFileConstraint(baseName string, src []byte) (constraint.Expr, error) {
	explicit, err := parseHeaderConstraint(src)
	if err != nil {
		return nil, fmt.Errorf("parse build constraint in %s: %w", baseName, err)
	}
	implicit := implicitFilenameConstraint(baseName)
	return simplifyConstraint(joinAnd(explicit, implicit)), nil
}

func parseHeaderConstraint(src []byte) (constraint.Expr, error) {
	var goBuild constraint.Expr
	var plusBuilds []constraint.Expr

	scanner := bufio.NewScanner(bytes.NewReader(src))
	inBlockComment := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if inBlockComment {
			if idx := strings.Index(line, "*/"); idx >= 0 {
				inBlockComment = false
				line = strings.TrimSpace(line[idx+2:])
			} else {
				continue
			}
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/*") {
			if !strings.Contains(line[2:], "*/") {
				inBlockComment = true
			}
			continue
		}
		if strings.HasPrefix(line, "//") {
			if constraint.IsGoBuild(line) {
				expr, err := constraint.Parse(line)
				if err != nil {
					return nil, err
				}
				goBuild = expr
			} else if constraint.IsPlusBuild(line) {
				expr, err := constraint.Parse(line)
				if err != nil {
					return nil, err
				}
				plusBuilds = append(plusBuilds, expr)
			}
			continue
		}
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if goBuild != nil {
		return goBuild, nil
	}
	var combined constraint.Expr
	for _, expr := range plusBuilds {
		combined = joinAnd(combined, expr)
	}
	return combined, nil
}

// implicitFilenameConstraint implements the go/build filename suffix rule (*_GOOS.go,
// *_GOARCH.go, and *_GOOS_GOARCH.go).
func implicitFilenameConstraint(baseName string) constraint.Expr {
	stem := strings.TrimSuffix(baseName, ".go")
	stem = strings.TrimSuffix(stem, "_test")
	idx := strings.IndexByte(stem, '_')
	if idx < 0 {
		return nil
	}
	fields := strings.Split(stem[idx+1:], "_")
	n := len(fields)
	if n >= 2 && knownGOOS[fields[n-2]] && knownGOARCH[fields[n-1]] {
		return &constraint.AndExpr{
			X: &constraint.TagExpr{Tag: fields[n-2]},
			Y: &constraint.TagExpr{Tag: fields[n-1]},
		}
	}
	if n >= 1 {
		last := fields[n-1]
		if knownGOOS[last] || knownGOARCH[last] {
			return &constraint.TagExpr{Tag: last}
		}
	}
	return nil
}

// CoversConstraint reports whether provider holds on every Go target where consumer holds.
func CoversConstraint(provider, consumer constraint.Expr) bool {
	if provider == nil {
		return true
	}
	negProvider := &constraint.NotExpr{X: provider}
	if consumer == nil {
		return !isConstraintSatisfiable(negProvider)
	}
	return !isConstraintSatisfiable(&constraint.AndExpr{X: consumer, Y: negProvider})
}

// EquivalentConstraints reports whether a and b select the exact same set of Go targets.
func EquivalentConstraints(a, b constraint.Expr) bool {
	return CoversConstraint(a, b) && CoversConstraint(b, a)
}

// AreMutuallyExclusive reports whether a and b never hold simultaneously on any Go target.
func AreMutuallyExclusive(a, b constraint.Expr) bool {
	if a == nil && b == nil {
		return false
	}
	if a == nil {
		return !isConstraintSatisfiable(b)
	}
	if b == nil {
		return !isConstraintSatisfiable(a)
	}
	return !isConstraintSatisfiable(&constraint.AndExpr{X: a, Y: b})
}

func isConstraintSatisfiable(expr constraint.Expr) bool {
	if expr == nil {
		return true
	}
	osSet := map[string]bool{
		"linux":   true,
		"darwin":  true,
		"windows": true,
		"plan9":   true,
	}
	archSet := map[string]bool{
		"amd64":   true,
		"arm64":   true,
		"riscv64": true,
	}
	customSet := make(map[string]bool)
	collectConstraintTags(expr, osSet, archSet, customSet)

	osList := sortedMapKeys(osSet)
	archList := sortedMapKeys(archSet)
	customList := sortedMapKeys(customSet)
	if len(customList) > 12 {
		customList = customList[:12]
	}
	limit := 1 << len(customList)

	for _, goos := range osList {
		for _, goarch := range archList {
			for mask := range limit {
				ok := expr.Eval(func(tag string) bool {
					if tag == "unix" {
						return unixGOOS[goos]
					}
					if tag == "linux" && goos == "android" {
						return true
					}
					if tag == "darwin" && goos == "ios" {
						return true
					}
					if knownGOOS[tag] {
						return tag == goos
					}
					if knownGOARCH[tag] {
						return tag == goarch
					}
					idx := slices.Index(customList, tag)
					return idx >= 0 && (mask&(1<<idx)) != 0
				})
				if ok {
					return true
				}
			}
		}
	}
	return false
}

func collectConstraintTags(expr constraint.Expr, osSet, archSet, customSet map[string]bool) {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		switch {
		case e.Tag == "unix":
		case knownGOOS[e.Tag]:
			osSet[e.Tag] = true
		case knownGOARCH[e.Tag]:
			archSet[e.Tag] = true
		default:
			customSet[e.Tag] = true
		}
	case *constraint.NotExpr:
		collectConstraintTags(e.X, osSet, archSet, customSet)
	case *constraint.AndExpr:
		collectConstraintTags(e.X, osSet, archSet, customSet)
		collectConstraintTags(e.Y, osSet, archSet, customSet)
	case *constraint.OrExpr:
		collectConstraintTags(e.X, osSet, archSet, customSet)
		collectConstraintTags(e.Y, osSet, archSet, customSet)
	}
}

func sortedMapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// CombineEmptyPartitionConstraints synthesizes the //go:build constraint for an empty partition.
// If any source file in the partition builds unconditionally, the partition has no constraint.
func CombineEmptyPartitionConstraints(exprs []constraint.Expr) constraint.Expr {
	if len(exprs) == 0 {
		return nil
	}
	var acc constraint.Expr
	for _, e := range exprs {
		if e == nil {
			return nil
		}
		acc = joinOr(acc, e)
	}
	return simplifyConstraint(acc)
}

func joinAnd(a, b constraint.Expr) constraint.Expr {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return &constraint.AndExpr{X: a, Y: b}
}

func joinOr(a, b constraint.Expr) constraint.Expr {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return &constraint.OrExpr{X: a, Y: b}
}

func simplifyConstraint(expr constraint.Expr) constraint.Expr {
	if expr == nil {
		return nil
	}
	switch e := expr.(type) {
	case *constraint.TagExpr:
		return e
	case *constraint.NotExpr:
		inner := simplifyConstraint(e.X)
		if inner == nil {
			return nil
		}
		if notInner, ok := inner.(*constraint.NotExpr); ok {
			return notInner.X
		}
		return &constraint.NotExpr{X: inner}
	case *constraint.AndExpr:
		terms := flattenAnd(e)
		dedup := deduplicateExprs(terms)
		if len(dedup) == 0 {
			return nil
		}
		out := dedup[0]
		for _, next := range dedup[1:] {
			out = &constraint.AndExpr{X: out, Y: next}
		}
		return out
	case *constraint.OrExpr:
		terms := flattenOr(e)
		dedup := deduplicateExprs(terms)
		if len(dedup) == 0 {
			return nil
		}
		out := dedup[0]
		for _, next := range dedup[1:] {
			out = &constraint.OrExpr{X: out, Y: next}
		}
		return out
	default:
		return expr
	}
}

func flattenAnd(expr constraint.Expr) []constraint.Expr {
	if and, ok := expr.(*constraint.AndExpr); ok {
		return append(flattenAnd(and.X), flattenAnd(and.Y)...)
	}
	s := simplifyConstraint(expr)
	if s == nil {
		return nil
	}
	return []constraint.Expr{s}
}

func flattenOr(expr constraint.Expr) []constraint.Expr {
	if or, ok := expr.(*constraint.OrExpr); ok {
		return append(flattenOr(or.X), flattenOr(or.Y)...)
	}
	s := simplifyConstraint(expr)
	if s == nil {
		return nil
	}
	return []constraint.Expr{s}
}

func deduplicateExprs(exprs []constraint.Expr) []constraint.Expr {
	seen := make(map[string]bool, len(exprs))
	out := make([]constraint.Expr, 0, len(exprs))
	for _, e := range exprs {
		key := canonicalConstraintKey(e)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	return out
}

func canonicalConstraintKey(expr constraint.Expr) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *constraint.TagExpr:
		return e.Tag
	case *constraint.NotExpr:
		return "!(" + canonicalConstraintKey(e.X) + ")"
	case *constraint.AndExpr:
		parts := flattenAnd(e)
		keys := make([]string, len(parts))
		for i, p := range parts {
			keys[i] = canonicalConstraintKey(p)
		}
		slices.Sort(keys)
		return "and(" + strings.Join(keys, ",") + ")"
	case *constraint.OrExpr:
		parts := flattenOr(e)
		keys := make([]string, len(parts))
		for i, p := range parts {
			keys[i] = canonicalConstraintKey(p)
		}
		slices.Sort(keys)
		return "or(" + strings.Join(keys, ",") + ")"
	default:
		return expr.String()
	}
}
