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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCopyrightIn(t *testing.T) {
	lines := []string{
		"2. Grant of Copyright License. Subject to the terms",
		"   Copyright [yyyy] [name of copyright owner]",
		" * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.",
		"// Copyright 2014 The Go Authors.  All rights reserved.",
		"// Revisions Copyright © 2000-2007 Vita Nuova Holdings Limited. */",
		"// The above copyright notice shall be included.",
		"// Copyright 2014 The Go Authors.  All rights reserved.",
	}
	want := []string{
		"Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.",
		"Copyright 2014 The Go Authors. All rights reserved.",
		"Copyright © 2000-2007 Vita Nuova Holdings Limited.",
	}
	if got := copyrightIn(lines); !slices.Equal(got, want) {
		t.Errorf("copyrightIn() = %q, want %q", got, want)
	}
}

func TestHeaderLinesKeepsLicenseBlocksOnly(t *testing.T) {
	src := "//go:build linux\n\n" +
		"// Copyright 2018 The Made Up Authors.\n" +
		"//\n" +
		"// Licensed under the Apache License, Version 2.0 (the \"License\").\n" +
		"\n" +
		"// Package made documents the package.\n" +
		"package made\n"
	got := strings.Join(headerLines(src), "\n")
	if !strings.Contains(got, "Licensed under the Apache License") || strings.Contains(got, "go:build") || strings.Contains(got, "documents the package") {
		t.Errorf("headerLines() = %q, want only the license block", got)
	}
}

func TestTextBodyDropsOnlyLeadingCopyright(t *testing.T) {
	got := textBody([]string{"Copyright 2009 The Made Up Authors.\r\n\r\nGrant text.  \r\nCopyright 2010 Inside.\r\n"})
	want := "Grant text.\nCopyright 2010 Inside.\n"
	if got != want {
		t.Errorf("textBody() = %q, want %q", got, want)
	}
}

func TestLicenseFilesInRequiresPrimaryFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("no license here"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := licenseFilesIn(dir); err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("licenseFilesIn(without a license) error = %v, want an error that names %s", err, dir)
	}

	for _, name := range []string{"license.go", "PATENTS", "LICENSE.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("text"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := licenseFilesIn(dir)
	if err != nil {
		t.Fatalf("licenseFilesIn() error: %v", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if want := []string{"LICENSE.txt", "PATENTS"}; !slices.Equal(names, want) {
		t.Errorf("licenseFilesIn() = %q, want %q", names, want)
	}
}
