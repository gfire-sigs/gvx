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
	"reflect"
	"strings"
	"testing"
)

func fakeHostEnv(m map[string]string) lookupEnv {
	return func(key string) (string, bool) {
		v, ok := m[key]
		return v, ok
	}
}

func TestResolveEnvEntry(t *testing.T) {
	host := fakeHostEnv(map[string]string{"HOME": "/h", "EMPTY": ""})
	for _, tc := range []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"A=1", "A=1", true},
		{"A=", "A=", true},
		{"A=b=c", "A=b=c", true},
		{`A="quoted"`, `A="quoted"`, true},
		{"HOME", "HOME=/h", true},
		{"EMPTY", "EMPTY=", true},
		{"UNSET", "", false},
	} {
		got, ok, err := resolveEnvEntry(tc.in, host)
		if err != nil || ok != tc.wantOK || got != tc.want {
			t.Errorf("resolveEnvEntry(%q) = (%q, %v, %v), want (%q, %v, nil)", tc.in, got, ok, err, tc.want, tc.wantOK)
		}
	}
}

func TestResolveEnvEntryRejectsBadNames(t *testing.T) {
	for _, in := range []string{"", "=value", "A B=1", "A\tB", " A=1"} {
		if got, _, err := resolveEnvEntry(in, fakeHostEnv(nil)); err == nil {
			t.Errorf("resolveEnvEntry(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	file := "# comment\n\nA=1\r\n   B=two words\nHOME\nUNSET\n\t# indented comment\nC=\"x\"\nD=#not-a-comment\n"
	got, err := parseEnvFile(strings.NewReader(file), fakeHostEnv(map[string]string{"HOME": "/h"}))
	if err != nil {
		t.Fatalf("parseEnvFile: %v", err)
	}
	want := []string{"A=1", "B=two words", "HOME=/h", `C="x"`, "D=#not-a-comment"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseEnvFile = %q, want %q", got, want)
	}
}

func TestParseEnvFileNamesTheBadLine(t *testing.T) {
	_, err := parseEnvFile(strings.NewReader("A=1\nB C=2\n"), fakeHostEnv(nil))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("parseEnvFile = %v, want an error that names line 2", err)
	}
}
