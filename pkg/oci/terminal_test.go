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

package oci

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadLineTakesOneLineAndLeavesTheRest(t *testing.T) {
	in := strings.NewReader("first\r\nsecond\nthird")
	for _, want := range []string{"first", "second", "third", ""} {
		got, err := ReadLine(in)
		if err != nil || got != want {
			t.Fatalf("ReadLine = %q, %v, want %q", got, err, want)
		}
	}
}

func TestReadPasswordReadsOneLineWhenInputIsNotATerminal(t *testing.T) {
	var prompt bytes.Buffer
	got, err := ReadPassword(strings.NewReader("s3cret\nignored\n"), &prompt)
	if err != nil || got != "s3cret" {
		t.Fatalf("ReadPassword = %q, %v, want s3cret", got, err)
	}
	if prompt.Len() != 0 {
		t.Errorf("a non-terminal read wrote the prompt %q", prompt.String())
	}
}

func TestIsTerminalRejectsPipesFilesAndOtherReaders(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	file, err := os.Create(filepath.Join(t.TempDir(), "plain"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for name, v := range map[string]any{"pipe": r, "regular file": file, "reader": strings.NewReader(""), "nil": nil} {
		if IsTerminal(v) {
			t.Errorf("IsTerminal(%s) = true, want false", name)
		}
	}
}
