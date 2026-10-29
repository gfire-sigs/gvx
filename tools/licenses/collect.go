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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Names of the components that do not come from a module path.
const (
	stdName    = "std"
	gvisorName = "github.com/google/gvisor"
)

// shippedTargets are the platforms that ship rungv.
var shippedTargets = []struct{ goos, goarch string }{
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"windows", "arm64"},
	{"linux", "amd64"},
	{"linux", "arm64"},
}

// group orders the components of the document: the standard library, then
// gVisor, then the third-party modules.
type group int

const (
	groupStd group = iota
	groupGVisor
	groupModule
)

// component is one licensed unit of the rungv binary.
type component struct {
	name, version string
	group         group
	notes         []string
	// replacement is the local path that replaces the module, if any.
	replacement string
	copyright   []string
	// body is the normalized license text. Components with equal bodies share one printed text.
	body string
	spdx string
}

// componentSpec gathers the inputs of newComponent.
type componentSpec struct {
	name, version, replacement string
	group                      group
	notes                      []string
	copyright                  []string
	// licenses holds the contents of the license files, in the order that they print.
	licenses []string
}

// newComponent builds a component and detects its SPDX expression.
func newComponent(spec componentSpec, refs []reference) component {
	body := textBody(spec.licenses)
	return component{
		name:        spec.name,
		version:     spec.version,
		group:       spec.group,
		notes:       spec.notes,
		replacement: spec.replacement,
		copyright:   spec.copyright,
		body:        body,
		spdx:        spdxExpression(body, refs),
	}
}

// document is everything that the generated text file and the README table show.
type document struct {
	goVersion  string
	components []component
	notices    []notice
	embeds     []embedEntry
}

// notice is a header text whose license is not Apache-2.0, with the files that carry it.
type notice struct {
	text      string
	spdx      string
	copyright []string
	paths     []string
}

// embedEntry names one file that a package of the binary embeds.
type embedEntry struct {
	importPath string
	file       string
	owner      string
}

// listedPackage holds the fields of go list -json output that the command reads.
type listedPackage struct {
	ImportPath string
	Standard   bool
	Dir        string
	EmbedFiles []string
	Module     *listedModule
}

// listedModule describes the module of a package.
type listedModule struct {
	Path    string
	Version string
	Main    bool
	Dir     string
	Replace *listedModule
}

// inventory is the union of the packages of all shipped targets.
type inventory struct {
	modules     map[string]*listedModule
	moduleDirs  map[string]map[string]bool
	stdDirs     map[string]bool
	stdPackages map[string]bool
	embeds      map[string]embedEntry
}

// collectDocument runs go list for every shipped target and reads the license data.
// It returns the warnings that do not stop the command.
func collectDocument(root string) (document, []string, error) {
	inv, err := collectInventory(root)
	if err != nil {
		return document{}, nil, err
	}
	goroot, goVersion, err := goEnv(root)
	if err != nil {
		return document{}, nil, err
	}
	refs, err := loadReferences()
	if err != nil {
		return document{}, nil, err
	}
	repoFiles, err := repoSourceFiles(root)
	if err != nil {
		return document{}, nil, err
	}
	linkedFiles, err := linkedSourceFiles(inv, goroot)
	if err != nil {
		return document{}, nil, err
	}
	scan, err := scanSources(append(repoFiles, linkedFiles...))
	if err != nil {
		return document{}, nil, err
	}

	std, err := stdComponent(goroot, goVersion, inv, refs)
	if err != nil {
		return document{}, nil, err
	}
	gvisor, err := gvisorComponent(root, scan, refs)
	if err != nil {
		return document{}, nil, err
	}
	comps := []component{std, gvisor}
	for _, path := range sortedKeys(inv.modules) {
		c, err := moduleComponent(inv, path, refs)
		if err != nil {
			return document{}, nil, err
		}
		comps = append(comps, c)
	}

	var warnings []string
	for _, c := range comps {
		if c.spdx == noAssertion {
			warnings = append(warnings, fmt.Sprintf("no SPDX text matches %s %s; its identifier is %s", c.name, c.version, noAssertion))
		}
	}
	notices, noticeWarnings := noticeDocuments(scan, refs)
	warnings = append(warnings, noticeWarnings...)
	doc := document{
		goVersion:  goVersion,
		components: comps,
		notices:    notices,
		embeds:     inv.sortedEmbeds(),
	}
	return doc, warnings, nil
}

// goEnv returns the root of the Go distribution and its version.
func goEnv(root string) (goroot, goVersion string, err error) {
	cmd := exec.Command("go", "env", "-json", "GOROOT", "GOVERSION")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("go env: %w", err)
	}
	var env struct{ GOROOT, GOVERSION string }
	if err := json.Unmarshal(out, &env); err != nil {
		return "", "", fmt.Errorf("go env: %w", err)
	}
	return env.GOROOT, env.GOVERSION, nil
}

// collectInventory runs go list for each shipped target with CGO_ENABLED=0.
func collectInventory(root string) (inventory, error) {
	inv := inventory{
		modules:     map[string]*listedModule{},
		moduleDirs:  map[string]map[string]bool{},
		stdDirs:     map[string]bool{},
		stdPackages: map[string]bool{},
		embeds:      map[string]embedEntry{},
	}
	for _, t := range shippedTargets {
		pkgs, err := goList(root, t.goos, t.goarch)
		if err != nil {
			return inventory{}, err
		}
		for _, p := range pkgs {
			if err := inv.add(p); err != nil {
				return inventory{}, err
			}
		}
	}
	return inv, nil
}

// goList returns the packages that rungv links for one target.
func goList(root, goos, goarch string) ([]listedPackage, error) {
	cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/rungv")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list for %s/%s: %w: %s", goos, goarch, err, strings.TrimSpace(stderr.String()))
	}
	dec := json.NewDecoder(&stdout)
	var pkgs []listedPackage
	for dec.More() {
		var p listedPackage
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("go list for %s/%s: %w", goos, goarch, err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// add merges one package into the inventory.
func (inv *inventory) add(p listedPackage) error {
	var owner string
	switch {
	case p.Standard:
		owner = stdName
		inv.stdPackages[p.ImportPath] = true
		if p.Dir != "" {
			inv.stdDirs[p.Dir] = true
		}
	case p.Module == nil:
		return fmt.Errorf("package %s belongs to no module and is not in the standard library", p.ImportPath)
	case p.Module.Main:
		owner = gvisorName
	default:
		owner = p.Module.Path
		inv.modules[owner] = p.Module
		if inv.moduleDirs[owner] == nil {
			inv.moduleDirs[owner] = map[string]bool{}
		}
		if p.Dir != "" {
			inv.moduleDirs[owner][p.Dir] = true
		}
	}
	for _, f := range p.EmbedFiles {
		inv.embeds[p.ImportPath+" "+f] = embedEntry{importPath: p.ImportPath, file: f, owner: owner}
	}
	return nil
}

// sortedEmbeds returns the embedded files sorted by import path and file name.
func (inv inventory) sortedEmbeds() []embedEntry {
	out := make([]embedEntry, 0, len(inv.embeds))
	for _, e := range inv.embeds {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b embedEntry) int {
		if c := strings.Compare(a.importPath, b.importPath); c != 0 {
			return c
		}
		return strings.Compare(a.file, b.file)
	})
	return out
}

// stdComponent describes the Go standard library. The vendored modules of the
// standard library must carry the same LICENSE text as the Go project.
func stdComponent(goroot, goVersion string, inv inventory, refs []reference) (component, error) {
	files, err := stdLicenseFiles(goroot)
	if err != nil {
		return component{}, err
	}
	texts, err := readFiles(files)
	if err != nil {
		return component{}, err
	}
	vendored, err := vendoredInStd(goroot, inv.stdPackages)
	if err != nil {
		return component{}, err
	}
	goLicense := textBody(texts[:1])
	for _, mod := range vendored {
		data, err := os.ReadFile(filepath.Join(goroot, "src", "vendor", filepath.FromSlash(mod), "LICENSE"))
		if err != nil {
			return component{}, fmt.Errorf("vendored module %s: %w", mod, err)
		}
		if textBody([]string{string(data)}) != goLicense {
			return component{}, fmt.Errorf("vendored module %s has a LICENSE text that differs from the Go LICENSE", mod)
		}
	}
	var notes []string
	if len(vendored) > 0 {
		notes = append(notes, "includes the vendored packages "+strings.Join(vendored, ", ")+", which carry the same license text")
	}
	copyright, err := sourceCopyrights(sortedKeys(inv.stdDirs))
	if err != nil {
		return component{}, err
	}
	return newComponent(componentSpec{
		name:      stdName,
		version:   goVersion,
		group:     groupStd,
		notes:     notes,
		copyright: appendDistinct(licenseCopyrights(texts), copyright...),
		licenses:  texts,
	}, refs), nil
}

// stdLicenseFiles returns the LICENSE file and the PATENTS file of the Go distribution.
// Some packagers keep the LICENSE file one directory above GOROOT.
func stdLicenseFiles(goroot string) ([]string, error) {
	dirs := []string{goroot, filepath.Dir(goroot)}
	license := firstExisting(dirs, "LICENSE")
	if license == "" {
		return nil, fmt.Errorf("the Go LICENSE file is in neither %s nor %s", dirs[0], dirs[1])
	}
	data, err := os.ReadFile(license)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(data), "The Go Authors") {
		return nil, fmt.Errorf("%s does not name The Go Authors", license)
	}
	files := []string{license}
	if patents := firstExisting(dirs, "PATENTS"); patents != "" {
		files = append(files, patents)
	}
	return files, nil
}

// firstExisting returns the first dir/name path that exists, or the empty string.
func firstExisting(dirs []string, name string) string {
	for _, dir := range dirs {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// vendoredInStd returns the vendored modules of the standard library that the
// binary links, sorted by path.
func vendoredInStd(goroot string, stdPackages map[string]bool) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(goroot, "src", "vendor", "modules.txt"))
	if err != nil {
		return nil, fmt.Errorf("read the vendor list of the standard library: %w", err)
	}
	var used []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "#" {
			continue
		}
		mod := fields[1]
		for pkg := range stdPackages {
			if pkg == "vendor/"+mod || strings.HasPrefix(pkg, "vendor/"+mod+"/") {
				used = append(used, mod)
				break
			}
		}
	}
	slices.Sort(used)
	return used, nil
}

// gvisorComponent describes the code of this repository: upstream gVisor and gvx.
func gvisorComponent(root string, scan repoScan, refs []reference) (component, error) {
	files, err := licenseFilesIn(root)
	if err != nil {
		return component{}, err
	}
	texts, err := readFiles(files)
	if err != nil {
		return component{}, err
	}
	commit, err := os.ReadFile(filepath.Join(root, "UPSTREAM_COMMIT"))
	if err != nil {
		return component{}, err
	}
	return newComponent(componentSpec{
		name:      gvisorName,
		version:   strings.TrimSpace(string(commit)),
		group:     groupGVisor,
		notes:     []string{"covers this repository (z.gfire.dev/gvx) and the upstream gVisor code that it contains"},
		copyright: appendDistinct(licenseCopyrights(texts), scan.apacheCopyrights...),
		licenses:  texts,
	}, refs), nil
}

// moduleComponent describes one third-party module.
func moduleComponent(inv inventory, path string, refs []reference) (component, error) {
	m := inv.modules[path]
	files, err := licenseFilesIn(m.Dir)
	if err != nil {
		return component{}, fmt.Errorf("module %s: %w", path, err)
	}
	texts, err := readFiles(files)
	if err != nil {
		return component{}, err
	}
	sources, err := sourceCopyrights(sortedKeys(inv.moduleDirs[path]))
	if err != nil {
		return component{}, err
	}
	spec := componentSpec{
		name:      path,
		version:   m.Version,
		group:     groupModule,
		copyright: appendDistinct(licenseCopyrights(texts), sources...),
		licenses:  texts,
	}
	if m.Replace != nil {
		spec.replacement = m.Replace.Path
		spec.notes = []string{"replaced by " + m.Replace.Path + " in this repository"}
	}
	return newComponent(spec, refs), nil
}

// licenseNamePrefixes name the files that carry license or notice text.
var licenseNamePrefixes = []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS"}

// primaryNamePrefixes name the files that every module must carry.
var primaryNamePrefixes = []string{"LICENSE", "LICENCE", "COPYING"}

// licenseFilesIn returns the license and notice files of dir, sorted by name.
// It fails when dir has no LICENSE, LICENCE, or COPYING file.
func licenseFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	primary := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || sourceExtensions[filepath.Ext(name)] {
			continue
		}
		if slices.ContainsFunc(licenseNamePrefixes, func(p string) bool { return matchNamePrefix(name, p) }) {
			files = append(files, filepath.Join(dir, name))
		}
		if slices.ContainsFunc(primaryNamePrefixes, func(p string) bool { return matchNamePrefix(name, p) }) {
			primary = true
		}
	}
	if !primary {
		return nil, fmt.Errorf("no LICENSE, LICENCE, or COPYING file in %s", dir)
	}
	return files, nil
}

// matchNamePrefix reports whether name is prefix, optionally followed by a
// separator and a suffix, in any letter case.
func matchNamePrefix(name, prefix string) bool {
	upper := strings.ToUpper(name)
	if !strings.HasPrefix(upper, prefix) {
		return false
	}
	rest := upper[len(prefix):]
	return rest == "" || strings.ContainsRune(".-_", rune(rest[0]))
}

// readFiles returns the contents of the named files in the given order.
func readFiles(paths []string) ([]string, error) {
	texts := make([]string, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		texts = append(texts, string(data))
	}
	return texts, nil
}

// sourceCopyrights returns the distinct copyright notices in the headers of the
// source files of dirs. The dirs are read in the given order.
func sourceCopyrights(dirs []string) ([]string, error) {
	var out []string
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !isSourceFile(e.Name()) {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
			out = appendDistinct(out, copyrightIn(headerLines(string(src)))...)
		}
	}
	return out, nil
}

// licenseCopyrights returns the distinct copyright notices of license texts.
func licenseCopyrights(texts []string) []string {
	var out []string
	for _, text := range texts {
		out = appendDistinct(out, copyrightIn(normalizeLines(text))...)
	}
	return out
}

// sortedKeys returns the keys of m in sorted order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// targetNames returns the shipped targets as GOOS/GOARCH pairs.
func targetNames() []string {
	names := make([]string, 0, len(shippedTargets))
	for _, t := range shippedTargets {
		names = append(names, t.goos+"/"+t.goarch)
	}
	return names
}
