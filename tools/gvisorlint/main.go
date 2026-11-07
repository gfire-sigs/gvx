// Package main is a `go vet` tool that runs the gVisor analyzers on plain `go`.
//
// Upstream gVisor runs these analyzers through Bazel and nogo. This tool runs
// them through `go vet -vettool`, so the Go build cache stores the results and
// each GOOS and GOARCH pair uses the files of its own build. The tool applies
// the suppressions of upstream `nogo.yaml` and the narrow baseline in
// baseline.txt. Read docs/gvisorlint.md for the procedure.
//
// Usage:
//
//	go build -o "$PWD/gvisorlint" ./tools/gvisorlint
//	GOOS=linux GOARCH=amd64 go vet -vettool="$PWD/gvisorlint" ./...
package main

import (
	"maps"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/ctrlflow"
	"golang.org/x/tools/go/analysis/unitchecker"

	"z.gfire.dev/gvx/tools/checklocks"
	"z.gfire.dev/gvx/tools/gvisorlint/checkconst"
	"z.gfire.dev/gvx/tools/gvisorlint/checklinkname"
)

// analyzers lists every analyzer that the tool runs.
func analyzers() []*analysis.Analyzer {
	list := []*analysis.Analyzer{
		checklocksOnMainModule(),
		skipStandardLibrary(checkconst.Analyzer),
		checklinkname.Analyzer,
	}
	for _, a := range list {
		filterReports(a, defaultFilter)
	}
	return list
}

// inMainModule reports whether the package belongs to the module that `go vet`
// checks. The go command leaves the version of the main module empty.
func inMainModule(pass *analysis.Pass) bool {
	return pass.Module != nil && pass.Module.Version == ""
}

// skipStandardLibrary returns a copy of the analyzer that does nothing for a
// package outside a module. Annotations of the analyzer exist only in module
// code, so the facts of the standard library would only cost time.
func skipStandardLibrary(a *analysis.Analyzer) *analysis.Analyzer {
	skipping := *a
	skipping.Run = func(pass *analysis.Pass) (any, error) {
		if pass.Module == nil {
			return nil, nil
		}
		return a.Run(pass)
	}
	return &skipping
}

// checklocksOnMainModule returns a copy of the checklocks analyzer that builds
// SSA form and analyzes locks only for packages of the main module.
//
// The original analyzer requires buildssa, so the driver would build SSA form
// for every dependency, and the cost of the standard library would dominate the
// run. Those packages carry no lock annotations. The copy keeps the ctrlflow
// requirement, because the SSA builder needs the facts about functions that
// never return, and runs buildssa itself when it needs the result.
func checklocksOnMainModule() *analysis.Analyzer {
	lazy := *checklocks.Analyzer
	lazy.Requires = []*analysis.Analyzer{ctrlflow.Analyzer}
	lazy.Run = func(pass *analysis.Pass) (any, error) {
		if !inMainModule(pass) {
			return nil, nil
		}
		ssa, err := buildssa.Analyzer.Run(pass)
		if err != nil {
			return nil, err
		}
		withSSA := *pass
		withSSA.ResultOf = maps.Clone(pass.ResultOf)
		withSSA.ResultOf[buildssa.Analyzer] = ssa
		return checklocks.Analyzer.Run(&withSSA)
	}
	return &lazy
}

func main() { unitchecker.Main(analyzers()...) }
