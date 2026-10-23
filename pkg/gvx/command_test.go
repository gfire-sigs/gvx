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

package gvx

import (
	"errors"
	"reflect"
	"testing"

	"z.gfire.dev/gvx/pkg/oci"
)

func TestComposeCommand(t *testing.T) {
	git := oci.RuntimeConfig{Entrypoint: []string{"git"}, Cmd: []string{"--help"}}
	shell := oci.RuntimeConfig{Cmd: []string{"/bin/sh"}}
	for _, tc := range []struct {
		name string
		img  oci.RuntimeConfig
		src  commandSource
		want []string
	}{
		{"image defaults", git, commandSource{}, []string{"git", "--help"}},
		{"cmd replaces image cmd and keeps entrypoint", git, commandSource{Cmd: []string{"status"}}, []string{"git", "status"}},
		{"image without entrypoint runs the cmd", shell, commandSource{Cmd: []string{"echo", "hi"}}, []string{"echo", "hi"}},
		{"entrypoint override drops the image cmd", git, commandSource{Entrypoint: []string{"sh"}, EntrypointSet: true}, []string{"sh"}},
		{"entrypoint override keeps the cmd of the caller", git, commandSource{Entrypoint: []string{"sh", "-c"}, EntrypointSet: true, Cmd: []string{"id"}}, []string{"sh", "-c", "id"}},
		{"empty entrypoint override clears the entrypoint", git, commandSource{EntrypointSet: true, Cmd: []string{"id"}}, []string{"id"}},
		{"argv replaces entrypoint and cmd", git, commandSource{Argv: []string{"sh", "-c", "true"}}, []string{"sh", "-c", "true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := composeCommand(tc.img, tc.src)
			if err != nil {
				t.Fatalf("composeCommand: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("composeCommand = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComposeCommandReportsMissingCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		img  oci.RuntimeConfig
		src  commandSource
	}{
		{"image has no command", oci.RuntimeConfig{}, commandSource{}},
		{"entrypoint cleared and no cmd", oci.RuntimeConfig{Entrypoint: []string{"git"}}, commandSource{EntrypointSet: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := composeCommand(tc.img, tc.src); !errors.Is(err, errNoCommand) {
				t.Fatalf("composeCommand = %v, want %v", err, errNoCommand)
			}
		})
	}
}

func TestComposeCommandCopiesArgv(t *testing.T) {
	argv := []string{"a", "b"}
	got, err := composeCommand(oci.RuntimeConfig{}, commandSource{Argv: argv})
	if err != nil {
		t.Fatal(err)
	}
	got[0] = "changed"
	if argv[0] != "a" {
		t.Errorf("composeCommand returned the slice of the caller: argv[0] = %q", argv[0])
	}
}

func TestMergeEnv(t *testing.T) {
	got, err := mergeEnv(
		[]string{"PATH=/bin", "LANG=C", "A=1"},
		[]string{"LANG=en", "NEW=x", "A=2", "NEW=y", "EMPTY="})
	if err != nil {
		t.Fatalf("mergeEnv: %v", err)
	}
	want := []string{"PATH=/bin", "LANG=en", "A=2", "NEW=y", "EMPTY="}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergeEnv = %q, want %q (an override keeps the position of the image entry, a new key goes last, a later override wins)", got, want)
	}
}

func TestMergeEnvRejectsEntriesWithoutKeyValue(t *testing.T) {
	for _, bad := range []string{"NOEQUALS", "=value", ""} {
		if _, err := mergeEnv(nil, []string{bad}); err == nil {
			t.Errorf("mergeEnv with override %q succeeded, want an error", bad)
		}
	}
}

func TestFinalizeEnvAddsOnlyMissingKeys(t *testing.T) {
	d := guestEnvDefaults{Home: "/home/bob", Hostname: "box", TTY: true}
	got := finalizeEnv([]string{"HOME=/custom", "TERM=vt100"}, d)
	want := []string{"HOME=/custom", "TERM=vt100", "PATH=" + defaultPath, "HOSTNAME=box"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("finalizeEnv = %q, want %q", got, want)
	}
	got = finalizeEnv(nil, guestEnvDefaults{Home: "/root", Hostname: "box"})
	want = []string{"PATH=" + defaultPath, "HOME=/root", "HOSTNAME=box"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("finalizeEnv without a terminal = %q, want %q (no TERM)", got, want)
	}
}

func TestApplyImageDefaultsComposesCommandAndMergesEnvironment(t *testing.T) {
	s := &Sandbox{cfg: Config{Cmd: []string{"status"}, Envv: []string{"LANG=en", "X=1"}}}
	img := oci.RuntimeConfig{Entrypoint: []string{"git"}, Cmd: []string{"--help"}, Env: []string{"PATH=/bin", "LANG=C"}}
	if err := s.applyImageDefaults(img); err != nil {
		t.Fatalf("applyImageDefaults: %v", err)
	}
	if want := []string{"git", "status"}; !reflect.DeepEqual(s.cfg.Argv, want) {
		t.Errorf("Argv = %q, want %q", s.cfg.Argv, want)
	}
	if want := []string{"PATH=/bin", "LANG=en", "X=1"}; !reflect.DeepEqual(s.cfg.Envv, want) {
		t.Errorf("Envv = %q, want %q", s.cfg.Envv, want)
	}
}

func TestApplyImageDefaultsRejectsABadEnvironmentEntry(t *testing.T) {
	s := &Sandbox{cfg: Config{Envv: []string{"NOEQUALS"}}}
	err := s.applyImageDefaults(oci.RuntimeConfig{Cmd: []string{"/bin/sh"}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("applyImageDefaults = %v, want an ErrInvalidConfig error", err)
	}
}
