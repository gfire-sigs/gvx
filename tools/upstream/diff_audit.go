package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
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

	Tier1Count int
	Tier2Count int
	Tier3Count int
	// Tier2Shadows counts Tier 2 files that replace an upstream file of the same path.
	Tier2Shadows int
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

var tier1Prefixes = []string{
	"cmd/rungv/",
	"cmd/containerd-shim-gvx-v2/",
	"pkg/gvx/",
	"pkg/oci/",
	"pkg/netbackend/",
	"pkg/hostlockdown/",
	"pkg/sentry/platform/whpx/",
	"pkg/sentry/platform/hvf/",
	"pkg/sentry/fsimpl/hostfs/",
	"pkg/sentry/fsimpl/ext4lite/",
	"pkg/sentry/platform/hvcommon/",
	"e2e/",
	"tools/upstream/",
	"tools/shiminterop/",
	"docs/",
	"internal/",
}

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
	name := strings.TrimSuffix(base, path.Ext(base))
	for tok := range strings.SplitSeq(name, "_") {
		switch tok {
		case "windows", "darwin", "xplat":
			return true
		}
	}
	return false
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
	if err != nil {
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

	st := &auditState{cfg: cfg, report: report, ruleUsed: make(map[string]bool)}
	seen := make(map[string]bool)
	fset := token.NewFileSet()

	walkErr := walkRepo(cfg.RootDir, func(abs, relSlash string, _ fs.DirEntry) error {
		if !isGoSource(relSlash) {
			return nil
		}
		tier := ClassifyFile(relSlash)
		if strings.HasSuffix(relSlash, ".go") {
			vs, err := auditFileImports(fset, abs, relSlash, tier)
			if err != nil {
				return err
			}
			for _, v := range vs {
				st.violations = append(st.violations, v)
			}
		}
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
