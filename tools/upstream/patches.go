package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/build"
	"go/build/constraint"
	"go/format"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// PatchKind states how a Tier 3 upstream file may differ from the pinned upstream commit.
type PatchKind int

const (
	// PatchExpand widens the build constraint to ExpandedBuildTag.
	PatchExpand PatchKind = iota + 1
	// PatchExpr sets an explicit build constraint expression.
	PatchExpr
	// PatchLinuxOnly narrows the build constraint so that only Linux targets compile the file.
	PatchLinuxOnly
	// PatchSeam registers a content edit that is not a build constraint change.
	PatchSeam
)

func (k PatchKind) String() string {
	switch k {
	case PatchExpand:
		return "expand"
	case PatchExpr:
		return "expr"
	case PatchLinuxOnly:
		return "linux-only"
	case PatchSeam:
		return "seam"
	default:
		return fmt.Sprintf("PatchKind(%d)", int(k))
	}
}

// Patch is one registered Tier 3 deviation from upstream.
type Patch struct {
	Kind PatchKind
	// Path is a slash-separated repository path. A trailing slash selects every file
	// directly inside that directory. A trailing "/**" selects every file below it.
	// Both forms are valid for PatchLinuxOnly only.
	Path string
	// Expr is the full constraint for PatchExpr, or an extra conjunct for PatchLinuxOnly.
	Expr string
	// Line is the 1-based line in the allowlist file, used in diagnostics.
	Line int
}

// PatchSet is the parsed content of buildtag_allowlist.txt.
type PatchSet struct {
	files map[string]Patch
	dirs  map[string]Patch
	trees map[string]Patch
}

var (
	errInvalidPatchRule  = errors.New("invalid allowlist rule")
	errDuplicatePatch    = errors.New("duplicate allowlist rule")
	errPatchNotPossible  = errors.New("build constraint patch cannot take effect")
	errInvalidConstraint = errors.New("invalid //go:build expression")
)

// nonLinuxTargets lists the Priority-0 host targets that must not compile Linux-only upstream code.
var nonLinuxTargets = []buildTarget{
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
}

// linuxTargets lists the Linux targets that upstream supports and that must keep building.
var linuxTargets = []buildTarget{
	{"linux", "amd64"},
	{"linux", "arm64"},
}

type buildTarget struct {
	goos, goarch string
}

// ParsePatchSet parses allowlist rules from r.
//
// Each rule is one line. Lines that start with # and blank lines are comments.
//
//	expand <path>                    widen to ExpandedBuildTag (a bare path means the same)
//	expr <path> <expression>         set //go:build to expression
//	linux-only <path|dir/|dir/**> [<expr>]
//	                                 narrow to Linux, optionally and-ed with expr; dir/ covers the
//	                                 files in dir, dir/** covers the whole tree below it
//	seam <path>                      register a content edit
func ParsePatchSet(r io.Reader) (*PatchSet, error) {
	ps := &PatchSet{files: make(map[string]Patch), dirs: make(map[string]Patch), trees: make(map[string]Patch)}
	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patch, err := parsePatchLine(line, lineNo)
		if err != nil {
			return nil, err
		}
		if err := ps.add(patch); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan allowlist: %w", err)
	}
	return ps, nil
}

func parsePatchLine(line string, lineNo int) (Patch, error) {
	keyword, rest, _ := strings.Cut(line, " ")
	rest = strings.TrimSpace(rest)
	switch keyword {
	case "expand", "seam":
		if rest == "" || strings.ContainsAny(rest, " \t") {
			return Patch{}, fmt.Errorf("%w: line %d: %s needs exactly one path", errInvalidPatchRule, lineNo, keyword)
		}
		kind := PatchExpand
		if keyword == "seam" {
			kind = PatchSeam
		}
		return newPatch(kind, rest, "", lineNo)
	case "expr":
		p, expr, ok := strings.Cut(rest, " ")
		if !ok || strings.TrimSpace(expr) == "" {
			return Patch{}, fmt.Errorf("%w: line %d: expr needs a path and an expression", errInvalidPatchRule, lineNo)
		}
		return newPatch(PatchExpr, p, strings.TrimSpace(expr), lineNo)
	case "linux-only":
		p, extra, _ := strings.Cut(rest, " ")
		if p == "" {
			return Patch{}, fmt.Errorf("%w: line %d: linux-only needs a path", errInvalidPatchRule, lineNo)
		}
		return newPatch(PatchLinuxOnly, p, strings.TrimSpace(extra), lineNo)
	}
	if !strings.ContainsAny(line, " \t") {
		return newPatch(PatchExpand, line, "", lineNo)
	}
	return Patch{}, fmt.Errorf("%w: line %d: unknown directive %q", errInvalidPatchRule, lineNo, keyword)
}

func newPatch(kind PatchKind, p, expr string, lineNo int) (Patch, error) {
	p = filepath.ToSlash(p)
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return Patch{}, fmt.Errorf("%w: line %d: path %q must be relative", errInvalidPatchRule, lineNo, p)
	}
	if (strings.HasSuffix(p, "/") || strings.HasSuffix(p, "/**")) && kind != PatchLinuxOnly {
		return Patch{}, fmt.Errorf("%w: line %d: %s rules cannot name a directory", errInvalidPatchRule, lineNo, kind)
	}
	if expr != "" {
		if _, err := constraint.Parse("//go:build " + expr); err != nil {
			return Patch{}, fmt.Errorf("%w: line %d: %q: %w", errInvalidConstraint, lineNo, expr, err)
		}
	}
	return Patch{Kind: kind, Path: p, Expr: expr, Line: lineNo}, nil
}

func (ps *PatchSet) add(p Patch) error {
	table, key := ps.files, p.Path
	switch {
	case strings.HasSuffix(p.Path, "/**"):
		table, key = ps.trees, strings.TrimSuffix(p.Path, "**")
	case strings.HasSuffix(p.Path, "/"):
		table = ps.dirs
	}
	if prev, dup := table[key]; dup {
		return fmt.Errorf("%w: %s on line %d repeats line %d", errDuplicatePatch, p.Path, p.Line, prev.Line)
	}
	table[key] = p
	return nil
}

// Lookup returns the rule that governs relSlash.
// A file rule wins over a directory rule, and a directory rule wins over the nearest tree rule.
func (ps *PatchSet) Lookup(relSlash string) (Patch, bool) {
	if p, ok := ps.files[relSlash]; ok {
		return p, true
	}
	if p, ok := ps.dirs[path.Dir(relSlash)+"/"]; ok {
		return p, true
	}
	for dir := path.Dir(relSlash); dir != "." && dir != "/"; dir = path.Dir(dir) {
		if p, ok := ps.trees[dir+"/"]; ok {
			return p, true
		}
	}
	return Patch{}, false
}

// LoadPatchSet parses the allowlist file at allowlistPath.
func LoadPatchSet(allowlistPath string) (_ *PatchSet, err error) {
	f, err := os.Open(allowlistPath)
	if err != nil {
		return nil, fmt.Errorf("open allowlist %s: %w", allowlistPath, err)
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	ps, err := ParsePatchSet(f)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist %s: %w", allowlistPath, err)
	}
	return ps, nil
}

// sanitizerTagSets lists the optional build tags that change which files the compiler selects.
// The first entry is the plain build. `go test -race`, `-msan`, and `-asan` each add one tag.
var sanitizerTagSets = [][]string{nil, {"race"}, {"msan"}, {"asan"}}

// buildCase is one compiler configuration: a target plus a sanitizer tag set.
type buildCase struct {
	target buildTarget
	tags   []string
}

func (c buildCase) String() string {
	if len(c.tags) == 0 {
		return c.target.goos + "/" + c.target.goarch
	}
	return c.target.goos + "/" + c.target.goarch + " with -tags " + strings.Join(c.tags, ",")
}

// buildCases returns every target and sanitizer tag set combination, in buildSet result order.
func buildCases(targets []buildTarget) []buildCase {
	cases := make([]buildCase, 0, len(targets)*len(sanitizerTagSets))
	for _, t := range targets {
		for _, tags := range sanitizerTagSets {
			cases = append(cases, buildCase{target: t, tags: tags})
		}
	}
	return cases
}

// matchesCase reports whether the Go toolchain compiles the file in configuration c.
// It applies file-name suffixes and //go:build lines exactly as `go build` does.
func matchesCase(name string, src []byte, c buildCase) (bool, error) {
	ctx := build.Context{
		GOOS:        c.target.goos,
		GOARCH:      c.target.goarch,
		Compiler:    "gc",
		BuildTags:   c.tags,
		ReleaseTags: build.Default.ReleaseTags,
		OpenFile: func(string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(src)), nil
		},
	}
	ok, err := ctx.MatchFile("/virtual", name)
	if err != nil {
		return false, fmt.Errorf("match build constraints of %s for %s: %w", name, c, err)
	}
	return ok, nil
}

// buildSet returns, for each case of buildCases(targets), whether the file compiles there.
// Sanitizer tags matter: a file tagged only `race` compiles on every OS under `go test -race`.
func buildSet(name string, src []byte, targets []buildTarget) ([]bool, error) {
	return evalCases(name, src, buildCases(targets))
}

// buildSetPlain evaluates the file without sanitizer tags, one result per target.
func buildSetPlain(name string, src []byte, targets []buildTarget) ([]bool, error) {
	cases := make([]buildCase, len(targets))
	for i, t := range targets {
		cases[i] = buildCase{target: t}
	}
	return evalCases(name, src, cases)
}

func evalCases(name string, src []byte, cases []buildCase) ([]bool, error) {
	out := make([]bool, len(cases))
	for i, c := range cases {
		ok, err := matchesCase(name, src, c)
		if err != nil {
			return nil, err
		}
		out[i] = ok
	}
	return out, nil
}

func anyTrue(v []bool) bool { return slices.Contains(v, true) }

func allTrue(v []bool) bool { return !slices.Contains(v, false) }

// goBuildExpr returns the normalized //go:build expression of src, or "" when absent.
func goBuildExpr(src []byte) (string, error) {
	for line := range strings.Lines(string(src)) {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case constraint.IsGoBuild(trimmed):
			expr, err := constraint.Parse(trimmed)
			if err != nil {
				return "", fmt.Errorf("%w: %q: %w", errInvalidConstraint, trimmed, err)
			}
			return expr.String(), nil
		case strings.HasPrefix(trimmed, "//"):
			continue
		}
		return "", nil
	}
	return "", nil
}

// setGoBuild replaces or inserts the //go:build line and drops legacy // +build lines.
// A stale // +build line would disagree with the new expression and fail `go vet`.
func setGoBuild(src []byte, expr string) []byte {
	var out bytes.Buffer
	replaced := false
	inHeader := true
	for line := range strings.Lines(string(src)) {
		trimmed := strings.TrimSpace(line)
		if inHeader && trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			inHeader = false
		}
		if inHeader && constraint.IsPlusBuild(trimmed) {
			continue
		}
		if inHeader && constraint.IsGoBuild(trimmed) {
			if !replaced {
				out.WriteString("//go:build " + expr + "\n")
				replaced = true
			}
			continue
		}
		out.WriteString(line)
	}
	if replaced {
		return out.Bytes()
	}
	return append([]byte("//go:build "+expr+"\n\n"), src...)
}

// linuxFenceExpr builds "linux && cur && extra" and drops conjuncts that repeat an earlier one.
func linuxFenceExpr(cur, extra string) (string, error) {
	var expr constraint.Expr = &constraint.TagExpr{Tag: "linux"}
	seen := map[string]bool{expr.String(): true}
	for _, part := range []string{cur, extra} {
		if part == "" {
			continue
		}
		parsed, err := constraint.Parse("//go:build " + part)
		if err != nil {
			return "", fmt.Errorf("%w: %q: %w", errInvalidConstraint, part, err)
		}
		if seen[parsed.String()] {
			continue
		}
		seen[parsed.String()] = true
		expr = &constraint.AndExpr{X: expr, Y: parsed}
	}
	return expr.String(), nil
}

// applyPatch returns the patched bytes for src under rule and whether they differ.
// The function is idempotent: a second call on its own output reports no change.
// A Linux-only rule leaves files untouched when no non-Linux target compiles them already.
func applyPatch(relSlash string, src []byte, rule Patch) ([]byte, bool, error) {
	switch rule.Kind {
	case PatchExpand:
		set, err := buildSetPlain(path.Base(relSlash), src, nonLinuxTargets)
		if err != nil {
			return nil, false, err
		}
		if allTrue(set) {
			return src, false, nil
		}
		return setIfDifferent(relSlash, src, strings.TrimPrefix(ExpandedBuildTag, "//go:build "))
	case PatchExpr:
		return setIfDifferent(relSlash, src, rule.Expr)
	case PatchLinuxOnly:
		set, err := buildSet(path.Base(relSlash), src, nonLinuxTargets)
		if err != nil {
			return nil, false, err
		}
		if !anyTrue(set) {
			return src, false, nil
		}
		cur, err := goBuildExpr(src)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", relSlash, err)
		}
		expr, err := linuxFenceExpr(cur, rule.Expr)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", relSlash, err)
		}
		return setIfDifferent(relSlash, src, expr)
	default:
		return src, false, nil
	}
}

func setIfDifferent(relSlash string, src []byte, expr string) ([]byte, bool, error) {
	norm, err := constraint.Parse("//go:build " + expr)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w: %q: %w", relSlash, errInvalidConstraint, expr, err)
	}
	cur, err := goBuildExpr(src)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", relSlash, err)
	}
	if cur == norm.String() {
		return src, false, nil
	}
	return setGoBuild(src, expr), true, nil
}

// RetagReport counts the files that RetagFiles changed.
type RetagReport struct {
	ModulePath int
	Patched    int
	Formatted  int
}

// RetagFiles applies the allowlist to every matching file under rootDir.
//
// It performs three idempotent steps: rewrite the upstream module path in Go and assembly
// files outside Tier 1, apply build constraint rules, and gofmt generated upstream files.
func RetagFiles(rootDir string, ps *PatchSet) (RetagReport, error) {
	var report RetagReport

	walkErr := walkRepo(rootDir, func(abs, relSlash string, d fs.DirEntry) error {
		if !isGoSource(relSlash) || ClassifyFile(relSlash) == Tier1Additive {
			return nil
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return fmt.Errorf("read %s: %w", relSlash, err)
		}
		updated := data
		if bytes.Contains(updated, []byte(upstreamModulePath)) {
			updated = rewriteModulePath(updated)
			report.ModulePath++
		}
		if isGeneratedUpstreamFile(relSlash) && strings.HasSuffix(relSlash, ".go") {
			formatted, err := format.Source(updated)
			if err != nil {
				return fmt.Errorf("format %s: %w", relSlash, err)
			}
			if !bytes.Equal(formatted, updated) {
				updated = formatted
				report.Formatted++
			}
		}
		if rule, ok := ps.Lookup(relSlash); ok && ClassifyFile(relSlash) == Tier3Upstream && !isTestFile(relSlash) {
			patched, changed, err := applyPatch(relSlash, updated, rule)
			if err != nil {
				return err
			}
			if changed {
				updated = patched
				report.Patched++
			}
		}
		if bytes.Equal(updated, data) {
			return nil
		}
		return writeFileAtomic(abs, updated, d)
	})
	if walkErr != nil {
		return report, walkErr
	}
	return report, nil
}

func writeFileAtomic(abs string, data []byte, d fs.DirEntry) error {
	mode := fs.FileMode(0o644)
	if info, err := d.Info(); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(abs), ".retag-*")
	if err != nil {
		return fmt.Errorf("create temp beside %s: %w", abs, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", tmpName, err), tmp.Close(), os.Remove(tmpName))
	}
	if err := tmp.Chmod(mode); err != nil {
		return errors.Join(fmt.Errorf("chmod %s: %w", tmpName, err), tmp.Close(), os.Remove(tmpName))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("close %s: %w", tmpName, err), os.Remove(tmpName))
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return errors.Join(fmt.Errorf("rename %s to %s: %w", tmpName, abs, err), os.Remove(tmpName))
	}
	return nil
}

func rewriteModulePath(src []byte) []byte {
	return bytes.ReplaceAll(src, []byte(upstreamModulePath), []byte(targetModulePath))
}

// isGoSource reports whether relSlash is a Go or assembly file that the Go toolchain builds.
func isGoSource(relSlash string) bool {
	return strings.HasSuffix(relSlash, ".go") || strings.HasSuffix(relSlash, ".s")
}

func isTestFile(relSlash string) bool {
	return strings.HasSuffix(relSlash, "_test.go")
}

// isGeneratedUpstreamFile reports whether upstream publishes the file as tool output.
func isGeneratedUpstreamFile(relSlash string) bool {
	base := path.Base(relSlash)
	return strings.Contains(base, "_autogen") || strings.HasSuffix(base, ".pb.go")
}

// walkRepo visits every regular file under rootDir except tooling and vendored trees.
func walkRepo(rootDir string, fn func(abs, relSlash string, d fs.DirEntry) error) error {
	return filepath.WalkDir(rootDir, func(abs string, d fs.DirEntry, err error) error {
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
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return fn(abs, relSlash, d)
	})
}

// All returns every rule, file rules, directory rules, and tree rules, in allowlist order.
func (ps *PatchSet) All() []Patch {
	out := make([]Patch, 0, len(ps.files)+len(ps.dirs)+len(ps.trees))
	for _, table := range []map[string]Patch{ps.files, ps.dirs, ps.trees} {
		for _, p := range table {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b Patch) int { return a.Line - b.Line })
	return out
}
