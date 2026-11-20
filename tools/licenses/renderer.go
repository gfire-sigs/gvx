// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	rendererLockRelPath       = "gpurenderer/third_party.lock"
	rendererComponentsRelPath = "gpurenderer/licenses/components.txt"
	rendererVenusRelPath      = "gpurenderer/licenses/venus-protocol.txt"
)

// rendererBaseComponents are always present in the renderer bundle alongside
// every BOTTLE.<formula> pinned in gpurenderer/third_party.lock.
var rendererBaseComponents = []string{
	"virglrenderer",
	"venus-protocol",
	"mesa",
}

// rendererBundleKinds lists the valid bundle source kinds in components.txt.
var rendererBundleKinds = map[string]bool{
	"pinned":      true,
	"mesa-source": true,
}

// checkRenderer verifies the license inputs of the GPU renderer bundle:
// every BOTTLE.<formula> of gpurenderer/third_party.lock and the components
// virglrenderer, venus-protocol, and mesa have a line in
// gpurenderer/licenses/components.txt; every line names a formula of the lock
// file or one of those three components; every SPDX field parses with the
// package's SPDX parser; and gpurenderer/licenses/venus-protocol.txt exists.
func checkRenderer(root string) error {
	expected, err := readRendererLockComponents(filepath.Join(root, filepath.FromSlash(rendererLockRelPath)))
	if err != nil {
		return err
	}
	for _, comp := range rendererBaseComponents {
		expected[comp] = true
	}

	manifest, err := readRendererManifest(filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath)))
	if err != nil {
		return err
	}

	var errs []error
	for _, comp := range sortedKeys(expected) {
		if !manifest[comp] {
			errs = append(errs, fmt.Errorf("%s: missing component %q", rendererComponentsRelPath, comp))
		}
	}
	for _, comp := range sortedKeys(manifest) {
		if !expected[comp] {
			errs = append(errs, fmt.Errorf("%s: unexpected component %q (not in %s)", rendererComponentsRelPath, comp, rendererLockRelPath))
		}
	}

	venusPath := filepath.Join(root, filepath.FromSlash(rendererVenusRelPath))
	info, err := os.Stat(venusPath)
	if err != nil {
		errs = append(errs, fmt.Errorf("stat %s: %w", rendererVenusRelPath, err))
	} else if !info.Mode().IsRegular() || info.Size() == 0 {
		errs = append(errs, fmt.Errorf("%s: must be a non-empty regular file", rendererVenusRelPath))
	}

	return errors.Join(errs...)
}

// readRendererLockComponents parses gpurenderer/third_party.lock and returns
// the set of formula names referenced by BOTTLE.<formula>.<field> keys.
func readRendererLockComponents(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rendererLockRelPath, err)
	}
	formulas := map[string]bool{}
	for idx, raw := range strings.Split(lfOnly(string(data)), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("%s:%d: malformed lock entry %q", rendererLockRelPath, idx+1, line)
		}
		rest, isBottle := strings.CutPrefix(strings.TrimSpace(key), "BOTTLE.")
		if !isBottle {
			continue
		}
		formula, field, ok := strings.Cut(rest, ".")
		if !ok || formula == "" || field == "" || strings.Contains(field, ".") {
			return nil, fmt.Errorf("%s:%d: malformed BOTTLE key %q", rendererLockRelPath, idx+1, key)
		}
		formulas[formula] = true
	}
	return formulas, nil
}

// readRendererManifest parses and validates gpurenderer/licenses/components.txt
// and returns the set of declared component names.
func readRendererManifest(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rendererComponentsRelPath, err)
	}
	components := map[string]bool{}
	var errs []error
	for idx, raw := range strings.Split(lfOnly(string(data)), "\n") {
		lineNo := idx + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 4 {
			errs = append(errs, fmt.Errorf("%s:%d: expected 4 pipe-separated fields, got %d", rendererComponentsRelPath, lineNo, len(fields)))
			continue
		}
		comp := strings.TrimSpace(fields[0])
		spdx := strings.TrimSpace(fields[1])
		licenseFile := strings.TrimSpace(fields[2])
		bundleKinds := strings.TrimSpace(fields[3])
		if comp == "" {
			errs = append(errs, fmt.Errorf("%s:%d: empty component name", rendererComponentsRelPath, lineNo))
			continue
		}
		if components[comp] {
			errs = append(errs, fmt.Errorf("%s:%d: duplicate component %q", rendererComponentsRelPath, lineNo, comp))
			continue
		}
		components[comp] = true

		if err := parseSPDXExpression(spdx); err != nil {
			errs = append(errs, fmt.Errorf("%s:%d: component %q has invalid SPDX expression %q: %w", rendererComponentsRelPath, lineNo, comp, spdx, err))
		}
		if wantFile := comp + ".txt"; licenseFile != wantFile {
			errs = append(errs, fmt.Errorf("%s:%d: component %q has invalid license file %q: want %q", rendererComponentsRelPath, lineNo, comp, licenseFile, wantFile))
		}
		if err := validateBundleKinds(bundleKinds); err != nil {
			errs = append(errs, fmt.Errorf("%s:%d: component %q has invalid bundle kinds %q: %w", rendererComponentsRelPath, lineNo, comp, bundleKinds, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return components, nil
}

func validateBundleKinds(raw string) error {
	if raw == "" {
		return errEmptyBundleKinds
	}
	var seen []string
	for part := range strings.SplitSeq(raw, ",") {
		kind := strings.TrimSpace(part)
		if !rendererBundleKinds[kind] {
			return fmt.Errorf("unknown bundle kind %q", kind)
		}
		if slices.Contains(seen, kind) {
			return fmt.Errorf("duplicate bundle kind %q", kind)
		}
		seen = append(seen, kind)
	}
	return nil
}

var (
	errEmptyBundleKinds     = errors.New("bundle kinds must not be empty")
	errEmptySPDX            = errors.New("empty expression")
	errUnexpectedSPDXEOF    = errors.New("unexpected end of expression")
	errMissingSPDXException = errors.New("expected license exception after WITH")
)

type spdxTokenKind int

const (
	spdxTokEOF spdxTokenKind = iota
	spdxTokLParen
	spdxTokRParen
	spdxTokAND
	spdxTokOR
	spdxTokWITH
	spdxTokIdent
)

type spdxToken struct {
	kind spdxTokenKind
	text string
}

// parseSPDXExpression validates expr against the SPDX license expression ABNF
// grammar (Annex D):
//
//	or-expr   = and-expr *( "OR" and-expr )
//	and-expr  = term *( "AND" term )
//	term      = "(" or-expr ")" / simple-expr [ "WITH" exception-id ]
func parseSPDXExpression(expr string) error {
	tokens := tokenizeSPDX(expr)
	if len(tokens) == 0 {
		return errEmptySPDX
	}
	p := spdxParser{tokens: tokens}
	if err := p.parseOr(); err != nil {
		return err
	}
	if tok := p.peek(); tok.kind != spdxTokEOF {
		return fmt.Errorf("unexpected token %q", tok.text)
	}
	return nil
}

func tokenizeSPDX(expr string) []spdxToken {
	var tokens []spdxToken
	for i := 0; i < len(expr); {
		c := expr[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if c == '(' {
			tokens = append(tokens, spdxToken{kind: spdxTokLParen, text: "("})
			i++
			continue
		}
		if c == ')' {
			tokens = append(tokens, spdxToken{kind: spdxTokRParen, text: ")"})
			i++
			continue
		}
		start := i
		for i < len(expr) && expr[i] != ' ' && expr[i] != '\t' && expr[i] != '(' && expr[i] != ')' {
			i++
		}
		word := expr[start:i]
		switch word {
		case "AND":
			tokens = append(tokens, spdxToken{kind: spdxTokAND, text: word})
		case "OR":
			tokens = append(tokens, spdxToken{kind: spdxTokOR, text: word})
		case "WITH":
			tokens = append(tokens, spdxToken{kind: spdxTokWITH, text: word})
		default:
			tokens = append(tokens, spdxToken{kind: spdxTokIdent, text: word})
		}
	}
	return tokens
}

type spdxParser struct {
	tokens []spdxToken
	pos    int
}

func (p *spdxParser) peek() spdxToken {
	if p.pos >= len(p.tokens) {
		return spdxToken{kind: spdxTokEOF}
	}
	return p.tokens[p.pos]
}

func (p *spdxParser) next() spdxToken {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func (p *spdxParser) parseOr() error {
	if err := p.parseAnd(); err != nil {
		return err
	}
	for p.peek().kind == spdxTokOR {
		p.next()
		if err := p.parseAnd(); err != nil {
			return err
		}
	}
	return nil
}

func (p *spdxParser) parseAnd() error {
	if err := p.parseTerm(); err != nil {
		return err
	}
	for p.peek().kind == spdxTokAND {
		p.next()
		if err := p.parseTerm(); err != nil {
			return err
		}
	}
	return nil
}

func (p *spdxParser) parseTerm() error {
	tok := p.peek()
	if tok.kind == spdxTokLParen {
		p.next()
		if err := p.parseOr(); err != nil {
			return err
		}
		if closeTok := p.next(); closeTok.kind != spdxTokRParen {
			return fmt.Errorf("expected ')', got %q", closeTok.text)
		}
		return nil
	}
	if tok.kind != spdxTokIdent {
		if tok.kind == spdxTokEOF {
			return errUnexpectedSPDXEOF
		}
		return fmt.Errorf("expected license identifier, got %q", tok.text)
	}
	p.next()
	if err := validateSPDXSimple(tok.text); err != nil {
		return err
	}
	if p.peek().kind == spdxTokWITH {
		p.next()
		exc := p.next()
		if exc.kind != spdxTokIdent {
			if exc.kind == spdxTokEOF {
				return errMissingSPDXException
			}
			return fmt.Errorf("expected license exception after WITH, got %q", exc.text)
		}
		if err := validateSPDXException(exc.text); err != nil {
			return err
		}
	}
	return nil
}

func validateSPDXSimple(id string) error {
	if id == noAssertion || id == "NONE" {
		return fmt.Errorf("disallowed license identifier %q", id)
	}
	// DocumentRef-<idstring>:LicenseRef-<idstring> or LicenseRef-<idstring>.
	if rest, ok := strings.CutPrefix(id, "DocumentRef-"); ok {
		docID, licPart, hasColon := strings.Cut(rest, ":")
		if !hasColon || !isSPDXIDString(docID) {
			return fmt.Errorf("invalid DocumentRef %q", id)
		}
		licRef, ok := strings.CutPrefix(licPart, "LicenseRef-")
		if !ok || !isSPDXIDString(licRef) {
			return fmt.Errorf("invalid LicenseRef in %q", id)
		}
		return nil
	}
	if licRef, ok := strings.CutPrefix(id, "LicenseRef-"); ok {
		if !isSPDXIDString(licRef) {
			return fmt.Errorf("invalid LicenseRef %q", id)
		}
		return nil
	}
	base := strings.TrimSuffix(id, "+")
	if !isSPDXIDString(base) {
		return fmt.Errorf("invalid license identifier %q", id)
	}
	return nil
}

func validateSPDXException(id string) error {
	if id == noAssertion || id == "NONE" || strings.HasPrefix(id, "LicenseRef-") || strings.HasPrefix(id, "DocumentRef-") {
		return fmt.Errorf("invalid license exception %q", id)
	}
	if !isSPDXIDString(id) {
		return fmt.Errorf("invalid license exception %q", id)
	}
	return nil
}

func isSPDXIDString(s string) bool {
	if s == "" {
		return false
	}
	if !isASCIIAlphaNum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isASCIIAlphaNum(c) && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNum(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}
