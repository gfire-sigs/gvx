package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"z.gfire.dev/gvx/tools/gostateify/stateify"
)

const (
	// ExpandedBuildTag is the multi-OS build constraint applied to allowlisted Tier 3 files.
	ExpandedBuildTag = "//go:build linux || windows || darwin"

	modulePrefix       = "z.gfire.dev/gvx/"
	legacyModulePrefix = "gvisor.dev/gvisor/"
)

var (
	errEmptyCommitSHA     = errors.New("upstream commit SHA is empty")
	errInvalidCommitSHA   = errors.New("upstream commit SHA must be 40 hexadecimal characters")
	errInvalidMaxRatio    = errors.New("max ratio must be within (0.0, 1.0]")
	errDiffBudgetExceeded = errors.New("touched upstream file ratio exceeds maximum budget")
	errForbiddenImport    = errors.New("package imports a forbidden or unlisted dependency")
	errManifestMismatch   = errors.New("sync_manifest.json records a different commit than UPSTREAM_COMMIT")
	errNoBaseline         = errors.New("upstream archive yields an empty baseline")
)

// IsolationTier classifies repository files according to Section 2.2 of docs/architecture.md.
type IsolationTier int

const (
	Tier1Additive IsolationTier = iota + 1
	Tier2Sibling
	Tier3Upstream
)

func (t IsolationTier) String() string {
	switch t {
	case Tier1Additive:
		return "tier1"
	case Tier2Sibling:
		return "tier2"
	case Tier3Upstream:
		return "tier3"
	default:
		return fmt.Sprintf("IsolationTier(%d)", int(t))
	}
}

// AuditReport summarizes the results of an upstream isolation and diff audit.
//
// Counts cover Go and assembly files. The upstream baseline is the number of such files in
// the pinned archive that file_mask.txt does not EXCLUDE and that lie outside Tier 1.
type AuditReport struct {
	UpstreamCommit string

	Tier1Count        int
	Tier1PackageCount int
	Tier2Count        int
	Tier2PackageCount int
	Tier3Count        int
	// Tier2Shadows counts Tier 2 files that replace an upstream file of the same path.
	Tier2Shadows int
	// Tier2XplatCount counts non-test *_xplat*.go files inside shared upstream packages.
	Tier2XplatCount int
	// Tier2XplatLOC sums lines across non-test *_xplat*.go files inside shared upstream packages.
	Tier2XplatLOC int
	// Tier2SharedPkgCount counts shared upstream packages that contain non-test *_xplat*.go files.
	Tier2SharedPkgCount int
	// TestsAdded counts gvx-written _test.go files in Tier 3 directories. They stay outside the budget.
	TestsAdded int

	UpstreamBaseline int
	MaskExcluded     int

	Pristine int
	Format   int
	Expand   int
	Fence    int
	Seam     int
	Shadow   int
	Added    int

	// NonGoPristine counts C, header, preassembled assembly, and proto files
	// that equal their upstream bytes. NonGoProtected counts those that differ
	// and that file_mask.txt PROTECTs. NonGoAdded counts those that upstream
	// does not have. These files stay outside the budget, because it counts Go
	// and assembly files. Any other difference fails the audit.
	NonGoPristine  int
	NonGoProtected int
	NonGoAdded     int
	// NonGoMissing counts upstream files of these kinds that the tree lacks and
	// that file_mask.txt does not EXCLUDE. The sync prunes them, so this count
	// informs and does not fail the audit.
	NonGoMissing int

	// Budgeted counts the files charged against the ceiling.
	Budgeted      int
	BudgetedRatio float64
	// StrictRatio also charges Linux fences, the strictest reading of SPEC section 2.2.
	StrictRatio float64

	AddedFiles []string
}

// budgetedCount returns the number of files charged against the ceiling.
func (r AuditReport) budgetedCount(countFences bool) int {
	n := r.Expand + r.Seam + r.Shadow + r.Added
	if countFences {
		n += r.Fence
	}
	return n
}

// AuditConfig carries every input of RunAudit.
type AuditConfig struct {
	RootDir  string
	Patches  *PatchSet
	Mask     *FileMask
	Upstream *UpstreamTree
	MaxRatio float64
	// CountFences charges Linux fences against the ceiling.
	CountFences bool
}

var tier1Prefixes = stateify.Tier1Prefixes()

// ClassifyFile returns the IsolationTier for a slash-normalized repository path.
func ClassifyFile(relPath string) IsolationTier {
	clean := filepath.ToSlash(relPath)
	for _, prefix := range tier1Prefixes {
		if strings.HasPrefix(clean, prefix) {
			return Tier1Additive
		}
	}
	if isSiblingOSFile(path.Base(clean)) {
		return Tier2Sibling
	}
	return Tier3Upstream
}

// isSiblingOSFile reports whether the file name carries a gvx sibling marker token.
// Tokens are separated by underscores: name_windows.go, name_darwin_arm64.go, name_xplat_test.go.
func isSiblingOSFile(base string) bool {
	return hasSiblingToken(base, "windows") || hasSiblingToken(base, "darwin") || hasSiblingToken(base, "xplat")
}

func hasSiblingToken(base, target string) bool {
	name := strings.TrimSuffix(base, path.Ext(base))
	for tok := range strings.SplitSeq(name, "_") {
		if tok == target {
			return true
		}
	}
	return false
}

func isXplatGoFile(relSlash string) bool {
	return strings.HasSuffix(relSlash, ".go") && !isTestFile(relSlash) && hasSiblingToken(path.Base(relSlash), "xplat")
}

func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	lines := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		lines++
	}
	return lines
}

// ValidateCommitSHA verifies that raw contains a 40-character lowercase or uppercase hex SHA.
func ValidateCommitSHA(raw string) (string, error) {
	sha := strings.TrimSpace(raw)
	if sha == "" {
		return "", errEmptyCommitSHA
	}
	if len(sha) != 40 {
		return "", fmt.Errorf("%w: got length %d", errInvalidCommitSHA, len(sha))
	}
	for i := range len(sha) {
		ch := sha[i]
		isHex := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
		if !isHex {
			return "", fmt.Errorf("%w: invalid byte %q at index %d", errInvalidCommitSHA, ch, i)
		}
	}
	return strings.ToLower(sha), nil
}

// ReadUpstreamCommit reads and validates rootDir/UPSTREAM_COMMIT.
func ReadUpstreamCommit(rootDir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(rootDir, "UPSTREAM_COMMIT"))
	if err != nil {
		return "", fmt.Errorf("read UPSTREAM_COMMIT: %w", err)
	}
	return ValidateCommitSHA(string(raw))
}

// ValidateManifest verifies that tools/upstream/sync_manifest.json records sha.
// A missing manifest is an error: the manifest pins the commit that the archive must match.
func ValidateManifest(rootDir, sha string) error {
	p := filepath.Join(rootDir, "tools", "upstream", "sync_manifest.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read sync manifest: %w", err)
	}
	var m SyncManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse sync manifest %s: %w", p, err)
	}
	if !strings.EqualFold(m.GoBranchSHA, sha) {
		return fmt.Errorf("%w: manifest %s, commit %s", errManifestMismatch, m.GoBranchSHA, sha)
	}
	return nil
}

// RunAudit enforces the SPEC section 2 isolation rules against the pinned upstream tree.
//
// It verifies import boundaries (2.1), tier membership and the diff ceiling (2.2), and that
// every edit of an upstream file is registered and byte-reproducible by RetagFiles (2.3).
// The returned error joins every violation so that one run lists them all.
func RunAudit(cfg AuditConfig) (AuditReport, error) {
	if cfg.MaxRatio <= 0 || cfg.MaxRatio > 1.0 {
		return AuditReport{}, fmt.Errorf("%w: %v", errInvalidMaxRatio, cfg.MaxRatio)
	}
	commit, err := ReadUpstreamCommit(cfg.RootDir)
	if err != nil && (cfg.Upstream == nil || !errors.Is(err, os.ErrNotExist)) {
		return AuditReport{}, err
	}
	report := AuditReport{UpstreamCommit: commit}
	if cfg.Upstream == nil {
		return report, errNoBaseline
	}
	report.UpstreamCommit = cfg.Upstream.SHA

	included, excluded := cfg.Upstream.UpstreamGoFiles(cfg.Mask)
	report.MaskExcluded = excluded
	for _, rel := range included {
		if ClassifyFile(rel) != Tier1Additive {
			report.UpstreamBaseline++
		}
	}
	if report.UpstreamBaseline == 0 {
		return report, errNoBaseline
	}

	st := &auditState{
		cfg:       cfg,
		report:    report,
		ruleUsed:  make(map[string]bool),
		xplatPkgs: make(map[string]bool),
	}

	boundaryReport, boundaryErr := VerifyBoundaries(BoundaryConfig{
		RootDir:  cfg.RootDir,
		Upstream: cfg.Upstream,
	})
	st.report.Tier1PackageCount = len(boundaryReport.Tier1Packages)
	st.report.Tier2PackageCount = len(boundaryReport.Tier2Packages)
	if boundaryErr != nil {
		if !errors.Is(boundaryErr, errForbiddenImport) && !errors.Is(boundaryErr, errUncoveredPackage) {
			return st.report, boundaryErr
		}
		st.violations = append(st.violations, flattenErrors(boundaryErr)...)
	}

	seen := make(map[string]bool)

	nonGoSeen := make(map[string]bool)
	walkErr := walkRepo(cfg.RootDir, func(abs, relSlash string, _ fs.DirEntry) error {
		if !isGoSource(relSlash) {
			if isNonGoSource(relSlash) && ClassifyFile(relSlash) != Tier1Additive {
				nonGoSeen[relSlash] = true
				return st.auditNonGoFile(abs, relSlash)
			}
			return nil
		}
		tier := ClassifyFile(relSlash)
		switch tier {
		case Tier1Additive:
			st.report.Tier1Count++
			return nil
		case Tier2Sibling:
			st.report.Tier2Count++
		case Tier3Upstream:
			st.report.Tier3Count++
		}
		seen[relSlash] = true
		return st.auditAgainstUpstream(abs, relSlash, tier)
	})
	if walkErr != nil {
		return st.report, walkErr
	}
	st.report.Tier2SharedPkgCount = len(st.xplatPkgs)
	st.countMissingNonGo(nonGoSeen)

	for _, rel := range included {
		if ClassifyFile(rel) == Tier1Additive || seen[rel] {
			continue
		}
		st.violations = append(st.violations, fmt.Errorf("%w: %s", errUnmaskedRemoval, rel))
	}
	st.checkStaleRules()
	slices.Sort(st.report.AddedFiles)

	st.report.Budgeted = st.report.budgetedCount(cfg.CountFences)
	st.report.BudgetedRatio = float64(st.report.Budgeted) / float64(st.report.UpstreamBaseline)
	st.report.StrictRatio = float64(st.report.budgetedCount(true)) / float64(st.report.UpstreamBaseline)
	if st.report.BudgetedRatio >= cfg.MaxRatio {
		st.violations = append(st.violations, fmt.Errorf(
			"%w: touched %d/%d files (%.4f >= %.4f)",
			errDiffBudgetExceeded, st.report.Budgeted, st.report.UpstreamBaseline, st.report.BudgetedRatio, cfg.MaxRatio,
		))
	}
	return st.report, errors.Join(st.violations...)
}

type auditState struct {
	cfg        AuditConfig
	report     AuditReport
	violations []error
	// ruleUsed marks the allowlist paths that edited at least one file.
	ruleUsed map[string]bool
	// xplatPkgs records shared package directories that hold non-test *_xplat*.go files.
	xplatPkgs map[string]bool
}

// auditNonGoFile compares one C, header, assembly, or proto file with upstream.
// The sync copies such a file without a rewrite, so an edit is a deviation that
// the Go retag cannot reproduce. Only file_mask.txt PROTECT can keep one.
func (st *auditState) auditNonGoFile(abs, relSlash string) error {
	repoBytes, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("read %s: %w", relSlash, err)
	}
	upBytes, inUpstream := st.cfg.Upstream.pristine(relSlash)
	switch {
	case !inUpstream:
		st.report.NonGoAdded++
	case bytes.Equal(repoBytes, upBytes):
		st.report.NonGoPristine++
	case st.cfg.Mask != nil && st.cfg.Mask.Decide(relSlash) == MaskProtect:
		st.report.NonGoProtected++
	default:
		st.violations = append(st.violations, fmt.Errorf("%w: %s", errNonGoModified, relSlash))
	}
	return nil
}

// countMissingNonGo counts the upstream C, header, assembly, and proto files
// that the tree lacks.
func (st *auditState) countMissingNonGo(seen map[string]bool) {
	for rel := range st.cfg.Upstream.Files {
		if !isNonGoSource(rel) || seen[rel] || ClassifyFile(rel) == Tier1Additive {
			continue
		}
		if st.cfg.Mask != nil && st.cfg.Mask.Decide(rel) == MaskExclude {
			continue
		}
		st.report.NonGoMissing++
	}
}

// checkStaleRules reports allowlist rules that no file needs. A stale rule hides a SPEC
// deviation that no longer exists, so the allowlist must shrink with the code.
// An expand rule counts as used when its file exists, because it asserts a cross-platform invariant.
func (st *auditState) checkStaleRules() {
	for _, rule := range st.cfg.Patches.All() {
		if st.ruleUsed[rule.Path] {
			continue
		}
		st.violations = append(st.violations, fmt.Errorf("%w: %s %s (allowlist line %d)", errStaleRule, rule.Kind, rule.Path, rule.Line))
	}
}

// auditAgainstUpstream compares one Tier 2 or Tier 3 file with upstream and updates the report.
func (st *auditState) auditAgainstUpstream(abs, relSlash string, tier IsolationTier) error {
	repoBytes, err := os.ReadFile(abs)
	if err != nil {
		return fmt.Errorf("read %s: %w", relSlash, err)
	}
	if tier == Tier2Sibling && isXplatGoFile(relSlash) {
		st.report.Tier2XplatCount++
		st.report.Tier2XplatLOC += countLines(repoBytes)
		st.xplatPkgs[path.Dir(relSlash)] = true
	}
	upBytes, inUpstream := st.cfg.Upstream.pristine(relSlash)

	if !inUpstream {
		switch {
		case tier == Tier2Sibling:
		case isTestFile(relSlash):
			st.report.TestsAdded++
		default:
			st.report.Added++
			st.report.AddedFiles = append(st.report.AddedFiles, relSlash)
		}
		return nil
	}

	if tier == Tier2Sibling {
		st.report.Tier2Shadows++
		if string(repoBytes) == string(upBytes) {
			st.report.Pristine++
			return nil
		}
		st.report.Shadow++
		if st.cfg.Mask == nil || st.cfg.Mask.Decide(relSlash) != MaskProtect {
			st.violations = append(st.violations, fmt.Errorf("%w: %s", errUnprotectedShadow, relSlash))
		}
		return nil
	}

	rule, hasRule := st.cfg.Patches.Lookup(relSlash)
	class, err := classifyAgainstUpstream(compareInput{
		relSlash: relSlash,
		repo:     repoBytes,
		upstream: upBytes,
		rule:     rule,
		hasRule:  hasRule,
	})
	if err != nil {
		st.violations = append(st.violations, err)
		return nil
	}
	if hasRule && rule.Kind == PatchExpand {
		st.ruleUsed[rule.Path] = true
		set, err := buildSetPlain(path.Base(relSlash), repoBytes, nonLinuxTargets)
		if err != nil {
			return err
		}
		if !allTrue(set) {
			st.violations = append(st.violations, fmt.Errorf("%w: %s must build on every non-Linux target (allowlist line %d)", errPatchMismatch, relSlash, rule.Line))
		}
	}
	if hasRule && rule.Kind == PatchLinuxOnly && (class == ClassPristine || class == ClassFormat) {
		// An untouched file in a linux-only scope must already be Linux-only, including under -race, -msan, and -asan.
		set, err := buildSet(path.Base(relSlash), repoBytes, nonLinuxTargets)
		if err != nil {
			return err
		}
		if i := slices.Index(set, true); i >= 0 {
			st.violations = append(st.violations, fmt.Errorf("%w: %s compiles on %s but allowlist line %d fences it; run -mode=retag",
				errPatchMismatch, relSlash, buildCases(nonLinuxTargets)[i], rule.Line))
		}
	}
	switch class {
	case ClassPristine:
		st.report.Pristine++
	case ClassFormat:
		st.report.Format++
	case ClassExpand:
		st.report.Expand++
		st.ruleUsed[rule.Path] = true
	case ClassFence:
		st.report.Fence++
		st.ruleUsed[rule.Path] = true
	case ClassSeam:
		st.report.Seam++
		st.ruleUsed[rule.Path] = true
	}
	return nil
}
