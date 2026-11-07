package main

import (
	_ "embed"
	"fmt"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// upstreamSuppressions holds the message patterns that upstream nogo.yaml
// suppresses for first-party code, grouped by analyzer.
//
// Each pattern reports an analysis limit and not a violation. The first
// pattern asks for new annotations. The others come from functions that lock
// and return without `+checklocksacquire` or `+checklocksrelease`.
var upstreamSuppressions = map[string][]string{
	"checklocks": {
		`^unexpected call to atomic function`,
		`^return with unexpected locks held`,
		`^incompatible return states`,
		`^may require checklocks annotation for`,
	},
}

//go:embed baseline.txt
var baselineText string

// rule drops the reports of one analyzer on one file when the message matches.
type rule struct {
	analyzer string
	file     string
	message  *regexp.Regexp
}

// reportFilter decides which diagnostics the tool drops.
type reportFilter struct {
	suppress map[string][]*regexp.Regexp
	baseline []rule
}

// defaultFilter applies the upstream suppressions and the embedded baseline.
var defaultFilter = mustParseFilter(baselineText)

func mustParseFilter(baseline string) *reportFilter {
	f, err := parseFilter(baseline)
	if err != nil {
		panic(fmt.Sprintf("gvisorlint: invalid baseline: %v", err))
	}
	return f
}

// parseFilter builds a filter from the text of a baseline file.
//
// A baseline line has three fields: the analyzer name, the repository path of
// the file, and a regular expression for the message. The path "-" selects a
// diagnostic without a position. A line that starts with "#" and an empty line
// have no effect.
func parseFilter(baseline string) (*reportFilter, error) {
	f := &reportFilter{suppress: make(map[string][]*regexp.Regexp)}
	for name, patterns := range upstreamSuppressions {
		for _, p := range patterns {
			f.suppress[name] = append(f.suppress[name], regexp.MustCompile(p))
		}
	}
	for n, line := range strings.Split(baseline, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want \"analyzer path message-regexp\"", n+1)
		}
		re, err := regexp.Compile(strings.TrimSpace(fields[2]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		f.baseline = append(f.baseline, rule{analyzer: fields[0], file: fields[1], message: re})
	}
	return f, nil
}

// drops reports whether the filter removes a diagnostic.
//
// A diagnostic without a position comes from a synthetic function that the
// SSA builder creates, such as the wrapper of a method value. Upstream nogo.yaml
// excludes these reports as well, because no source line can carry an annotation.
func (f *reportFilter) drops(analyzer string, file string, validPos bool, message string) bool {
	if analyzer == "checklocks" && !validPos {
		return true
	}
	for _, re := range f.suppress[analyzer] {
		if re.MatchString(message) {
			return true
		}
	}
	file = filepath.ToSlash(file)
	for _, r := range f.baseline {
		if r.analyzer != analyzer {
			continue
		}
		if r.file == "-" {
			if validPos {
				continue
			}
		} else if !strings.HasSuffix(file, "/"+r.file) {
			continue
		}
		if r.message.MatchString(message) {
			return true
		}
	}
	return false
}

// filterReports makes the analyzer discard the diagnostics that f drops. It
// also discards a diagnostic that the analyzer reports twice for one position,
// because checklocks analyzes a closure again for each call that inlines it.
func filterReports(a *analysis.Analyzer, f *reportFilter) {
	run := a.Run
	a.Run = func(pass *analysis.Pass) (any, error) {
		report := pass.Report
		type reported struct {
			pos     token.Pos
			message string
		}
		seen := make(map[reported]bool)
		pass.Report = func(d analysis.Diagnostic) {
			var file string
			if d.Pos != token.NoPos {
				file = pass.Fset.Position(d.Pos).Filename
			}
			if f.drops(a.Name, file, d.Pos != token.NoPos, d.Message) {
				return
			}
			if key := (reported{d.Pos, d.Message}); !seen[key] {
				seen[key] = true
				report(d)
			}
		}
		return run(pass)
	}
}
