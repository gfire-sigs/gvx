package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/build/constraint"
	"go/format"
	"path"
	"slices"
	"strings"
)

// FileClass states how one repository file relates to its pinned upstream counterpart.
type FileClass int

const (
	// ClassPristine means the bytes equal upstream after the module path rewrite.
	ClassPristine FileClass = iota + 1
	// ClassFormat means only whitespace or legacy // +build lines differ. The //go:build line is equal.
	ClassFormat
	// ClassExpand means the build constraint widens or sets an explicit expression under an allowlist rule.
	ClassExpand
	// ClassFence means the build constraint narrows to Linux under an allowlist rule.
	ClassFence
	// ClassSeam means a content edit registered with a seam rule.
	ClassSeam
	// ClassShadow means a Tier 2 file replaces an upstream file with different content.
	ClassShadow
)

var (
	errUnlistedBuildTag  = errors.New("build constraint differs from upstream without an allowlist rule")
	errUnauthorizedEdit  = errors.New("file content differs from upstream without a seam rule")
	errLinuxFileModified = errors.New("file with a _linux name differs from upstream")
	errPatchMismatch     = errors.New("build constraint does not match its allowlist rule")
	errRedundantPatch    = errors.New("allowlist rule edits a file that builds correctly without the edit")
	errUnprotectedShadow = errors.New("Tier 2 file replaces an upstream file but file_mask.txt does not PROTECT it")
	errStaleRule         = errors.New("allowlist rule matches no edited file")
	errUnmaskedRemoval   = errors.New("upstream file is missing but file_mask.txt does not EXCLUDE it")
	errNonGoModified     = errors.New("upstream C, header, assembly, or proto file differs from upstream and file_mask.txt does not PROTECT it")
	errNonGeneratedFmt   = errors.New("formatting differs from upstream in a hand-written file")
)

var knownGOOS = map[string]bool{
	"aix": true, "android": true, "darwin": true, "dragonfly": true, "freebsd": true,
	"hurd": true, "illumos": true, "ios": true, "js": true, "linux": true, "nacl": true,
	"netbsd": true, "openbsd": true, "plan9": true, "solaris": true, "wasip1": true,
	"windows": true, "zos": true,
}

var knownGOARCH = map[string]bool{
	"386": true, "amd64": true, "amd64p32": true, "arm": true, "armbe": true, "arm64": true,
	"arm64be": true, "loong64": true, "mips": true, "mipsle": true, "mips64": true,
	"mips64le": true, "mips64p32": true, "mips64p32le": true, "ppc": true, "ppc64": true,
	"ppc64le": true, "riscv": true, "riscv64": true, "s390": true, "s390x": true, "sparc": true,
	"sparc64": true, "wasm": true,
}

// filenameGOOS returns the GOOS implied by the file name suffix, or "" when none applies.
// It follows the go/build rules: name_GOOS, name_GOARCH, and name_GOOS_GOARCH before the extension.
func filenameGOOS(base string) string {
	name := strings.TrimSuffix(base, path.Ext(base))
	name = strings.TrimSuffix(name, "_test")
	_, tail, ok := strings.Cut(name, "_")
	if !ok {
		return ""
	}
	parts := strings.Split(tail, "_")
	n := len(parts)
	if n >= 2 && knownGOOS[parts[n-2]] && knownGOARCH[parts[n-1]] {
		return parts[n-2]
	}
	if knownGOOS[parts[n-1]] {
		return parts[n-1]
	}
	return ""
}

// canonicalForm strips build constraint lines and collapses formatting so that two files
// compare equal when only constraints or whitespace differ.
func canonicalForm(relSlash string, src []byte) []byte {
	var body bytes.Buffer
	inHeader := true
	blank := false
	for line := range strings.Lines(string(src)) {
		trimmed := strings.TrimSpace(line)
		if inHeader && trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			inHeader = false
		}
		if inHeader && (constraint.IsGoBuild(trimmed) || constraint.IsPlusBuild(trimmed)) {
			continue
		}
		if trimmed == "" {
			if blank {
				continue
			}
			blank = true
		} else {
			blank = false
		}
		body.WriteString(strings.TrimRight(line, " \t\r\n"))
		body.WriteByte('\n')
	}
	out := bytes.TrimLeft(body.Bytes(), "\n")
	if strings.HasSuffix(relSlash, ".go") {
		if formatted, err := format.Source(out); err == nil {
			return formatted
		}
	}
	return out
}

// compareInput carries the facts that classification needs.
type compareInput struct {
	relSlash string
	repo     []byte
	upstream []byte
	rule     Patch
	hasRule  bool
}

// classifyAgainstUpstream compares one Tier 3 file with its pristine upstream bytes.
func classifyAgainstUpstream(in compareInput) (FileClass, error) {
	if bytes.Equal(in.repo, in.upstream) {
		return ClassPristine, nil
	}
	base := path.Base(in.relSlash)
	if filenameGOOS(base) == "linux" {
		return 0, fmt.Errorf("%w: %s", errLinuxFileModified, in.relSlash)
	}
	if !bytes.Equal(canonicalForm(in.relSlash, in.repo), canonicalForm(in.relSlash, in.upstream)) {
		if in.hasRule && in.rule.Kind == PatchSeam {
			return ClassSeam, nil
		}
		return 0, fmt.Errorf("%w: %s", errUnauthorizedEdit, in.relSlash)
	}

	repoExpr, err := goBuildExpr(in.repo)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", in.relSlash, err)
	}
	upExpr, err := goBuildExpr(in.upstream)
	if err != nil {
		return 0, fmt.Errorf("%s: upstream: %w", in.relSlash, err)
	}
	if repoExpr == upExpr {
		if !isGeneratedUpstreamFile(in.relSlash) && strings.HasSuffix(in.relSlash, ".go") && !bytes.Equal(in.repo, in.upstream) {
			// Hand-written upstream code is gofmt-clean; a whitespace diff means someone edited it.
			if !onlyLegacyBuildLinesDiffer(in.repo, in.upstream) {
				return 0, fmt.Errorf("%w: %s", errNonGeneratedFmt, in.relSlash)
			}
		}
		return ClassFormat, nil
	}
	if !in.hasRule {
		return 0, fmt.Errorf("%w: %s", errUnlistedBuildTag, in.relSlash)
	}
	return verifyConstraintPatch(in, repoExpr)
}

// onlyLegacyBuildLinesDiffer reports whether removing // +build lines makes the two files byte-equal.
func onlyLegacyBuildLinesDiffer(repo, upstream []byte) bool {
	return bytes.Equal(dropPlusBuild(repo), dropPlusBuild(upstream))
}

func dropPlusBuild(src []byte) []byte {
	var out bytes.Buffer
	inHeader := true
	for line := range strings.Lines(string(src)) {
		trimmed := strings.TrimSpace(line)
		if inHeader && trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			inHeader = false
		}
		if inHeader && constraint.IsPlusBuild(trimmed) {
			continue
		}
		out.WriteString(line)
	}
	return out.Bytes()
}

// verifyConstraintPatch proves that the repo constraint is what the allowlist rule produces
// and that it keeps every Linux target building as before.
func verifyConstraintPatch(in compareInput, repoExpr string) (FileClass, error) {
	base := path.Base(in.relSlash)
	repoNonPlain, err := buildSetPlain(base, in.repo, nonLinuxTargets)
	if err != nil {
		return 0, err
	}
	repoNon, err := buildSet(base, in.repo, nonLinuxTargets)
	if err != nil {
		return 0, err
	}
	upNon, err := buildSet(base, in.upstream, nonLinuxTargets)
	if err != nil {
		return 0, err
	}
	repoLin, err := buildSet(base, in.repo, linuxTargets)
	if err != nil {
		return 0, err
	}
	upLin, err := buildSet(base, in.upstream, linuxTargets)
	if err != nil {
		return 0, err
	}
	switch in.rule.Kind {
	case PatchExpand:
		want := strings.TrimPrefix(ExpandedBuildTag, "//go:build ")
		if repoExpr != mustParseString(want) {
			return 0, fmt.Errorf("%w: %s has %q, rule on line %d wants %q", errPatchMismatch, in.relSlash, repoExpr, in.rule.Line, want)
		}
		if !allTrue(repoNonPlain) {
			return 0, fmt.Errorf("%w: %s does not build on every non-Linux target", errPatchMismatch, in.relSlash)
		}
		return ClassExpand, requireLinuxSuperset(in.relSlash, repoLin, upLin)
	case PatchExpr:
		if repoExpr != mustParseString(in.rule.Expr) {
			return 0, fmt.Errorf("%w: %s has %q, rule on line %d wants %q", errPatchMismatch, in.relSlash, repoExpr, in.rule.Line, in.rule.Expr)
		}
		return ClassExpand, nil
	case PatchLinuxOnly:
		if i := slices.Index(repoNon, true); i >= 0 {
			return 0, fmt.Errorf("%w: %s still builds on %s", errPatchMismatch, in.relSlash, buildCases(nonLinuxTargets)[i])
		}
		if !anyTrue(upNon) {
			return 0, fmt.Errorf("%w: %s", errRedundantPatch, in.relSlash)
		}
		cases := buildCases(linuxTargets)
		for i := range repoLin {
			if repoLin[i] && !upLin[i] {
				return 0, fmt.Errorf("%w: %s builds on %s where upstream does not", errPatchMismatch, in.relSlash, cases[i])
			}
			if in.rule.Expr == "" && upLin[i] && !repoLin[i] {
				return 0, fmt.Errorf("%w: %s stopped building on %s", errPatchMismatch, in.relSlash, cases[i])
			}
		}
		return ClassFence, nil
	case PatchSeam:
		return ClassSeam, nil
	default:
		return 0, fmt.Errorf("%w: %s has unknown rule kind", errPatchMismatch, in.relSlash)
	}
}

func requireLinuxSuperset(relSlash string, repoLin, upLin []bool) error {
	cases := buildCases(linuxTargets)
	for i := range upLin {
		if upLin[i] && !repoLin[i] {
			return fmt.Errorf("%w: %s stopped building on %s", errPatchMismatch, relSlash, cases[i])
		}
	}
	return nil
}

func mustParseString(expr string) string {
	parsed, err := constraint.Parse("//go:build " + expr)
	if err != nil {
		return expr
	}
	return parsed.String()
}
