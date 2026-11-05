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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

func TestRunTuneFlagsSetTheConfigTuning(t *testing.T) {
	rc, _, done, stderr := parse(t, "--tune", "net.nat.mtu=9000", "-tune", "net.dns.timeout=8s", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	if got := rc.cfg.Tuning.Int(tuning.NATMTU); got != 9000 {
		t.Errorf("net.nat.mtu = %d, want 9000", got)
	}
	if got := rc.cfg.Tuning.Duration(tuning.DNSTimeout); got != 8*time.Second {
		t.Errorf("net.dns.timeout = %v, want 8s", got)
	}
	if got := rc.cfg.Tuning.Int(tuning.NATUDPSessions); got != 512 {
		t.Errorf("net.nat.udp_sessions = %d, want the default 512", got)
	}
}

func TestRunTuneFileIsReadAndFlagsWin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "tune.json")
	if err := os.WriteFile(file, []byte(`{"net.nat.mtu": 9000, "net.nat.udp_sessions": 64}`), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, _, done, stderr := parse(t, "--tune-file", file, "--tune", "net.nat.mtu=1400", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	if got := rc.cfg.Tuning.Int(tuning.NATMTU); got != 1400 {
		t.Errorf("net.nat.mtu = %d, want 1400 from the flag, which wins over the file", got)
	}
	if got := rc.cfg.Tuning.Int(tuning.NATUDPSessions); got != 64 {
		t.Errorf("net.nat.udp_sessions = %d, want 64 from the file", got)
	}
}

func TestRunTuneErrorsAreUsageErrors(t *testing.T) {
	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte(`{"net.nat.nope": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"out of range", []string{"--tune", "net.nat.mtu=10"}, []string{"net.nat.mtu", "68 to 65535"}},
		{"unknown key", []string{"--tune", "net.nat.mtuu=10"}, []string{`unknown key "net.nat.mtuu"`}},
		{"missing value", []string{"--tune", "net.nat.mtu"}, []string{"want KEY=VALUE"}},
		{"unknown key in the file", []string{"--tune-file", badFile}, []string{"net.nat.nope", badFile}},
		{"missing file", []string{"--tune-file", filepath.Join(t.TempDir(), "none.json")}, []string{"--tune-file"}},
		{"range of a port list", []string{"-p", "1-2000", "--tune", "net.forward.max_port_range=1000"}, []string{"net.forward.max_port_range"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, code, done, stderr := parse(t, append(tc.args, "-image=x")...)
			if !done || code != 2 {
				t.Fatalf("parseRunArgs = (done %v, code %d), want a usage error with code 2", done, code)
			}
			for _, w := range tc.want {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr %q lacks %q", stderr, w)
				}
			}
		})
	}
}

func TestTuneListPrintsEveryEntry(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := tuneSubcommand([]string{"list"}, &out, &errOut); code != 0 {
		t.Fatalf("rungv tune list = %d, stderr %q", code, errOut.String())
	}
	text := out.String()
	for _, e := range tuning.Entries() {
		line := ""
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, e.Name+" ") {
				line = l
			}
		}
		if line == "" {
			t.Errorf("the list lacks %s", e.Name)
			continue
		}
		for _, part := range []string{e.Kind.String(), e.DefaultText(), e.RangeText(), e.Doc} {
			if !strings.Contains(line, part) {
				t.Errorf("the line of %s lacks %q: %s", e.Name, part, line)
			}
		}
	}
	if code := tuneSubcommand([]string{"show"}, &out, &errOut); code != 2 {
		t.Errorf("rungv tune show = %d, want the usage code 2", code)
	}
}

func TestTuneIsAListedCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := executeCLI(t.Context(), []string{"tune", "list"}, nil, &out, &errOut); code != 0 || !strings.Contains(out.String(), "net.nat.mtu") {
		t.Errorf("rungv tune list = (%d, %q, %q)", code, out.String(), errOut.String())
	}
}

func TestImageCommandsTakeTheTuneFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	code := executeCLI(t.Context(), []string{"images", "-cache-dir", t.TempDir(), "--tune", "oci.max_entries=0"}, nil, &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "oci.max_entries") {
		t.Errorf("rungv images --tune oci.max_entries=0 = (%d, %q), want a failure that names the key", code, errOut.String())
	}
	code = executeCLI(t.Context(), []string{"images", "-cache-dir", t.TempDir(), "--tune", "oci.max_entries=5"}, nil, &out, &errOut)
	if code != 0 {
		t.Errorf("rungv images --tune oci.max_entries=5 = %d, stderr %q", code, errOut.String())
	}
}
