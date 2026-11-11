package main

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	toolPath  string
	buildErr  error
)

// TestMain removes the directory of the tool binary after the tests.
func TestMain(m *testing.M) {
	code := m.Run()
	if toolPath != "" {
		os.RemoveAll(filepath.Dir(toolPath))
	}
	os.Exit(code)
}

// buildTool builds the real vet tool once for all tests.
func buildTool(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gvisorlint")
		if err != nil {
			buildErr = err
			return
		}
		name := "gvisorlint"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		toolPath = filepath.Join(dir, name)
		out, err := exec.Command("go", "build", "-o", toolPath, ".").CombinedOutput()
		if err != nil {
			buildErr = &buildError{err: err, out: string(out)}
		}
	})
	if buildErr != nil {
		t.Fatalf("build the vet tool: %v", buildErr)
	}
	return toolPath
}

type buildError struct {
	err error
	out string
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

// vetFixture runs `go vet -vettool` on a copy of the tree testdata/<name> in a new module.
func vetFixture(t *testing.T, name string) (output string, failed bool) {
	t.Helper()
	tool := buildTool(t)
	module := t.TempDir()
	if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte("module example.com/fixture\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("testdata", name)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dst := filepath.Join(module, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, content, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "vet", "-vettool="+tool, "./...")
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod")
	out, err := cmd.CombinedOutput()
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatalf("run go vet: %v", err)
	}
	return string(out), err != nil
}

func TestVetTool(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fixture string
		// want lists the substrings of the report. An empty list means that
		// the tool reports nothing.
		want []string
	}{
		{
			name:    "checklocks rejects a guarded field access without the lock",
			fixture: "locks_violation",
			want:    []string{"fixture.go:12:", "invalid field access, mu"},
		},
		{name: "checklocks accepts a forced line", fixture: "locks_forced"},
		{name: "checklocks accepts held locks and lock preconditions", fixture: "locks_clean"},
		{name: "checklocks drops a suggestion for an annotation", fixture: "locks_suppressed"},
		{
			name:    "checkconst rejects a wrong offset in an assembly file",
			fixture: "const_asm_wrong",
			want:    []string{"offsets.s:1:", `got value 16, wanted "8"`},
		},
		{name: "checkconst accepts a right offset in an assembly file", fixture: "const_asm_right"},
		{
			name:    "checkconst rejects a wrong size against an internal standard library type",
			fixture: "const_std_wrong",
			want:    []string{"fixture.go:13:", "wanted \"16\""},
		},
		{name: "checkconst accepts a right size against an internal standard library type", fixture: "const_std_right"},
		{
			name:    "checklinkname rejects a symbol that the standard library lacks",
			fixture: "linkname_missing",
			want:    []string{`remote symbol "gvxNoSuchFunction" not defined in package "runtime"`},
		},
		{
			name:    "checklinkname rejects a signature that differs from the standard library",
			fixture: "linkname_wrong",
			want:    []string{`symbol "nanotime" has signature`},
		},
		{name: "checklinkname accepts a signature that matches the standard library", fixture: "linkname_right"},
		{name: "checklinkname accepts a symbol that a function with a body defines", fixture: "linkname_push"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, failed := vetFixture(t, tc.fixture)
			if len(tc.want) == 0 {
				if failed || strings.TrimSpace(output) != "" {
					t.Fatalf("go vet reported on a clean fixture (failed=%v):\n%s", failed, output)
				}
				return
			}
			if !failed {
				t.Fatalf("go vet passed, want a report with %q\n%s", tc.want, output)
			}
			for _, w := range tc.want {
				if !strings.Contains(output, w) {
					t.Errorf("report lacks %q:\n%s", w, output)
				}
			}
		})
	}
}

func TestVetToolReportsOneViolationOnce(t *testing.T) {
	output, _ := vetFixture(t, "locks_violation")
	if got := strings.Count(output, "invalid field access"); got != 1 {
		t.Errorf("the report names the violation %d times, want 1:\n%s", got, output)
	}
}
