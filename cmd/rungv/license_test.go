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
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// hostModules returns the paths of the third-party modules that go list reports for
// this package on the host target. The shipped build uses CGO_ENABLED=0, so the list does too.
func hostModules(t *testing.T) []string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("find the go command: %v", err)
	}
	cmd := exec.Command(goTool, "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}", ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, stderr.String())
	}
	seen := map[string]bool{}
	var modules []string
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" && !seen[line] {
			seen[line] = true
			modules = append(modules, line)
		}
	}
	if len(modules) == 0 {
		t.Fatal("go list -deps reported no third-party modules")
	}
	return modules
}

func runLicense(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := executeCLI(context.Background(), append([]string{"license"}, args...), nil, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestLicenseCommandPrintsEveryNotice(t *testing.T) {
	code, stdout, stderr := runLicense(t)
	if code != 0 {
		t.Fatalf("rungv license exited with %d: %s", code, stderr)
	}
	for _, want := range []string{
		"Redistribution and use in source and binary forms",
		"The Go Authors",
		"Version 2.0, January 2004",
		"The gVisor Authors",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("rungv license output lacks %q", want)
		}
	}
	for _, module := range hostModules(t) {
		if !strings.Contains(stdout, module) {
			t.Errorf("rungv license output lacks the module %s", module)
		}
	}
}

func TestLicenseListNamesEveryModule(t *testing.T) {
	code, stdout, stderr := runLicense(t, "-list")
	if code != 0 {
		t.Fatalf("rungv license -list exited with %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	for _, module := range hostModules(t) {
		found := false
		for _, line := range lines {
			if strings.HasPrefix(line, module+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rungv license -list has no line for the module %s", module)
		}
	}
	for _, line := range lines {
		if strings.Count(line, " ") < 2 {
			t.Errorf("component line %q does not hold name, version, and SPDX-id", line)
		}
	}
}

// TestComponentIndexAcceptsCRLF checks the index of a notice file that a Windows
// checkout wrote with CRLF line endings.
func TestComponentIndexAcceptsCRLF(t *testing.T) {
	text := "intro\r\n\r\n" + componentListHeading + "\r\nstd go1.27.3 BSD-3-Clause\r\nexample.com/m v1.0.0 MIT\r\n\r\nbody\r\n"
	lines, ok := componentIndex(text)
	want := []string{"std go1.27.3 BSD-3-Clause", "example.com/m v1.0.0 MIT"}
	if !ok || strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("componentIndex() = (%q, %v), want (%q, true)", lines, ok, want)
	}
}

func TestLicenseRejectsArguments(t *testing.T) {
	code, stdout, stderr := runLicense(t, "extra")
	if code != 2 || stdout != "" || !strings.Contains(stderr, `unexpected argument "extra"`) {
		t.Fatalf("rungv license extra = (code %d, stdout %q, stderr %q), want a usage error", code, stdout, stderr)
	}
}
