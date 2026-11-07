package main

import (
	"strings"
	"testing"
)

func TestParseFilterRejectsMalformedLines(t *testing.T) {
	for name, baseline := range map[string]string{
		"missing regexp":  "checklocks pkg/a/b.go",
		"invalid regexp":  "checklocks pkg/a/b.go (",
		"missing path":    "checklocks",
		"only whitespace": "checklocks   ",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFilter(baseline); err == nil {
				t.Fatalf("parseFilter(%q) succeeded, want an error", baseline)
			}
		})
	}
}

func TestEmbeddedBaselineParses(t *testing.T) {
	if _, err := parseFilter(baselineText); err != nil {
		t.Fatalf("baseline.txt: %v", err)
	}
}

func TestFilterDrops(t *testing.T) {
	f, err := parseFilter(strings.Join([]string{
		"# A comment and an empty line have no effect.",
		"",
		`checklocks pkg/tcpip/stack/stack.go ^invalid field access, mu .* when accessing nics`,
		`checklinkname - ^remote symbol "runtime_canSpin" not defined in package "sync"$`,
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	const (
		stackFile = "/work/gvx/pkg/tcpip/stack/stack.go"
		otherFile = "/work/gvx/pkg/tcpip/stack/other.go"
	)
	for _, tc := range []struct {
		name     string
		analyzer string
		file     string
		validPos bool
		message  string
		want     bool
	}{
		{"upstream suppression of inferred annotations", "checklocks", otherFile, true, "may require checklocks annotation for mu, used with lock held 100% of the time", true},
		{"upstream suppression of atomic calls", "checklocks", otherFile, true, "unexpected call to atomic function", true},
		{"upstream suppression of return states", "checklocks", otherFile, true, "return with unexpected locks held (locks: &(x.mu) exclusively)", true},
		{"upstream suppression of incompatible returns", "checklocks", otherFile, true, "incompatible return states (first: no locks held, second: &(x.mu) exclusively)", true},
		{"synthetic function without a position", "checklocks", "", false, "must hold e.mu exclusively to call keepaliveTimerExpired, but not held", true},
		{"violation on a guarded field", "checklocks", otherFile, true, "invalid field access, mu (&(x.mu)) must be locked when accessing nics (locks: no locks held)", false},
		{"violation of a lock precondition", "checklocks", otherFile, true, "must hold s.mu non-exclusively (&(s.mu)) to call f, but not held", false},
		{"baseline entry on its file", "checklocks", stackFile, true, "invalid field access, mu (&(x.mu)) must be locked when accessing nics (locks: no locks held)", true},
		{"baseline entry on another file", "checklocks", otherFile, true, "invalid field access, mu (&(x.mu)) must be locked when accessing nics (locks: no locks held)", false},
		{"baseline entry with another message", "checklocks", stackFile, true, "invalid field access, mu (&(x.mu)) must be locked when accessing routes (locks: no locks held)", false},
		{"baseline entry of another analyzer", "checkconst", stackFile, true, "invalid field access, mu (&(x.mu)) must be locked when accessing nics", false},
		{"file name that only ends alike", "checklocks", "/work/gvx/pkg/tcpip/stack/xstack.go", true, "invalid field access, mu (&(x.mu)) must be locked when accessing nics", false},
		{"baseline entry without a position", "checklinkname", "", false, `remote symbol "runtime_canSpin" not defined in package "sync"`, true},
		{"baseline entry without a position skips a diagnostic with a position", "checklinkname", stackFile, true, `remote symbol "runtime_canSpin" not defined in package "sync"`, false},
		{"baseline entry without a position skips another symbol", "checklinkname", "", false, `remote symbol "runtime_x" not defined in package "sync"`, false},
		{"other analyzers keep diagnostics without a position", "checkconst", "", false, "got value 8, wanted 16", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.drops(tc.analyzer, tc.file, tc.validPos, tc.message); got != tc.want {
				t.Errorf("drops(%q, %q, %v, %q) = %v, want %v", tc.analyzer, tc.file, tc.validPos, tc.message, got, tc.want)
			}
		})
	}
}
