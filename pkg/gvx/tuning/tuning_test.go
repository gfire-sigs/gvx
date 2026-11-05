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

package tuning

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the tunables table in docs/cli.md")

const (
	tableBegin = "<!-- tuning:begin -->"
	tableEnd   = "<!-- tuning:end -->"
)

func TestZeroValuesHoldTheDefaults(t *testing.T) {
	var v Values
	if got := v.Int(NATMTU); got != 1500 {
		t.Errorf("net.nat.mtu = %d, want 1500", got)
	}
	if got := v.Int(NATUDPSessions); got != 512 {
		t.Errorf("net.nat.udp_sessions = %d, want 512", got)
	}
	if got := v.Duration(MemoryCgroupIdlePollInterval); got != 25*time.Millisecond {
		t.Errorf("memory.cgroup.idle_poll_interval = %v, want 25ms", got)
	}
	if got := v.Size(OCIMaxImageBytes); got != 128<<30 {
		t.Errorf("oci.max_image_bytes = %d, want 128 GiB", got)
	}
	for _, e := range Entries() {
		if got, ok := v.Get(e.Name); !ok || got != e.Default {
			t.Errorf("Get(%s) = %d, %v, want the default %d", e.Name, got, ok, e.Default)
		}
	}
}

func TestSetParsesEveryKindAndLeavesTheOriginalAlone(t *testing.T) {
	base := Values{}
	v, err := base.Set("net.nat.mtu", "9000")
	if err != nil {
		t.Fatal(err)
	}
	v, err = v.Set("net.nat.dial_timeout", "2500ms")
	if err != nil {
		t.Fatal(err)
	}
	v, err = v.Set("oci.max_json_bytes", "16MiB")
	if err != nil {
		t.Fatal(err)
	}
	if v.Int(NATMTU) != 9000 || v.Duration(NATDialTimeout) != 2500*time.Millisecond || v.Size(OCIMaxJSONBytes) != 16<<20 {
		t.Errorf("values = %d, %v, %d", v.Int(NATMTU), v.Duration(NATDialTimeout), v.Size(OCIMaxJSONBytes))
	}
	if base.Int(NATMTU) != 1500 {
		t.Errorf("Set changed the receiver: net.nat.mtu = %d", base.Int(NATMTU))
	}
}

func TestSetRejectsBadInputWithTheKeyAndTheRange(t *testing.T) {
	cases := []struct {
		name, key, text string
		want            []string
	}{
		{"below the range", "net.nat.mtu", "60", []string{"net.nat.mtu", "60", "68 to 65535"}},
		{"above the range", "net.nat.mtu", "70000", []string{"net.nat.mtu", "70000", "68 to 65535"}},
		{"duration range", "net.udp.idle_timeout", "5ms", []string{"net.udp.idle_timeout", "5ms", "10ms to 24h"}},
		{"size range", "oci.max_json_bytes", "1KiB", []string{"oci.max_json_bytes", "1KiB", "64KiB to 1GiB"}},
		{"not an integer", "net.nat.mtu", "big", []string{"net.nat.mtu", `"big"`, "integer"}},
		{"not a duration", "net.dns.timeout", "5", []string{"net.dns.timeout", `"5"`, "duration"}},
		{"unknown size unit", "oci.max_blob_bytes", "5x", []string{"oci.max_blob_bytes", "unit"}},
		{"unknown key", "net.nat.mtu2", "1", []string{`unknown key "net.nat.mtu2"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Values{}.Set(tc.key, tc.text)
			if err == nil {
				t.Fatal("Set returned no error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
		})
	}
}

func TestTypedSettersObeyTheRange(t *testing.T) {
	if _, err := (Values{}).WithInt(NATMTU, 67); err == nil || !strings.Contains(err.Error(), "net.nat.mtu") {
		t.Errorf("WithInt(67) error = %v, want one that names net.nat.mtu", err)
	}
	v, err := Values{}.WithInt(NATMTU, 68)
	if err != nil || v.Int(NATMTU) != 68 {
		t.Errorf("WithInt(68) = %d, %v", v.Int(NATMTU), err)
	}
	if _, err := (Values{}).WithDuration(NATDialTimeout, time.Nanosecond); err == nil {
		t.Error("WithDuration accepted 1ns")
	}
	if _, err := (Values{}).WithSize(OCIMaxBlobBytes, 1); err == nil {
		t.Error("WithSize accepted 1 byte")
	}
}

func TestSetReportsAnIntegerThatOverflowsAsTooLarge(t *testing.T) {
	for _, tc := range []struct{ key, text string }{
		{"net.nat.mtu", "99999999999999999999"},
		{"oci.max_json_bytes", "99999999999999999999"},
		{"oci.max_json_bytes", "99999999999999999999KiB"},
	} {
		_, err := Values{}.Set(tc.key, tc.text)
		if err == nil || !strings.Contains(err.Error(), "too large") || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("Set(%s, %s) error = %v, want one that names the key and says too large", tc.key, tc.text, err)
		}
	}
}

func TestFailedSettersReturnTheReceiverUnchanged(t *testing.T) {
	base, err := Values{}.Set("net.nat.mtu", "9000")
	if err != nil {
		t.Fatal(err)
	}
	for name, try := range map[string]func() (Values, error){
		"Set unknown key": func() (Values, error) { return base.Set("nope", "1") },
		"Set bad text":    func() (Values, error) { return base.Set("net.dns.timeout", "soon") },
		"Set range":       func() (Values, error) { return base.Set("net.nat.mtu", "1") },
		"WithInt":         func() (Values, error) { return base.WithInt(NATMTU, 1) },
		"WithDuration":    func() (Values, error) { return base.WithDuration(NATDialTimeout, time.Nanosecond) },
		"WithSize":        func() (Values, error) { return base.WithSize(OCIMaxBlobBytes, 1) },
	} {
		got, err := try()
		if err == nil {
			t.Errorf("%s returned no error", name)
		}
		if got.Int(NATMTU) != 9000 {
			t.Errorf("%s dropped the earlier setting: net.nat.mtu = %d, want 9000", name, got.Int(NATMTU))
		}
	}
}

func TestParseJSONReportsBadValuesInTheOrderOfTheNames(t *testing.T) {
	const text = `{"net.nat.udp_sessions": [1], "net.nat.mtu": null, "net.dns.timeout": {}}`
	want := `tuning: net.dns.timeout: want a string or a number
tuning: net.nat.mtu: want a string or a number
tuning: net.nat.udp_sessions: want a string or a number`
	for range 20 {
		_, err := ParseJSON([]byte(text))
		if err == nil || err.Error() != want {
			t.Fatalf("ParseJSON error = %v, want\n%s", err, want)
		}
	}
}

func TestParseReportsEveryBadPair(t *testing.T) {
	_, err := Parse(map[string]string{"net.nat.mtu": "1", "net.dns.timeout": "1h", "nope": "1"})
	if err == nil {
		t.Fatal("Parse returned no error")
	}
	for _, w := range []string{"net.nat.mtu", "net.dns.timeout", `"nope"`} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q lacks %q", err, w)
		}
	}
}

func TestParseJSONAcceptsStringsAndNumbers(t *testing.T) {
	v, err := ParseJSON([]byte(`{"net.nat.mtu": 9000, "net.dns.timeout": "3s", "oci.max_blob_bytes": "2GiB"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v.Int(NATMTU) != 9000 || v.Duration(DNSTimeout) != 3*time.Second || v.Size(OCIMaxBlobBytes) != 2<<30 {
		t.Errorf("values = %d, %v, %d", v.Int(NATMTU), v.Duration(DNSTimeout), v.Size(OCIMaxBlobBytes))
	}
	for name, text := range map[string]string{
		"array":         `[1]`,
		"nested value":  `{"net.nat.mtu": [1]}`,
		"null":          `{"net.nat.mtu": null}`,
		"unknown key":   `{"net.nat.nope": 1}`,
		"out of range":  `{"net.nat.mtu": 1}`,
		"trailing data": `{} {}`,
		"fraction":      `{"net.nat.mtu": 1500.5}`,
		"boolean":       `{"net.nat.mtu": true}`,
	} {
		if _, err := ParseJSON([]byte(text)); err == nil {
			t.Errorf("%s: ParseJSON(%s) returned no error", name, text)
		}
	}
}

func TestParseSizeUnits(t *testing.T) {
	for text, want := range map[string]int64{"4096": 4096, "4k": 4096, "4KiB": 4096, "2m": 2 << 20, "1GB": 1 << 30, "1t": 1 << 40, "7b": 7} {
		if got, err := parseSize(text); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v, want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", "-1", "1.5g", "9999999999t", "m"} {
		if _, err := parseSize(text); err == nil {
			t.Errorf("parseSize(%q) returned no error", text)
		}
	}
}

func TestFormatRoundTripsThroughSet(t *testing.T) {
	for _, e := range Entries() {
		for _, n := range []int64{e.Default, e.Min, e.Max} {
			v, err := Values{}.Set(e.Name, e.Format(n))
			if err != nil {
				t.Errorf("%s: Set(%q): %v", e.Name, e.Format(n), err)
				continue
			}
			if got, _ := v.Get(e.Name); got != n {
				t.Errorf("%s: round trip of %d gave %d", e.Name, n, got)
			}
		}
	}
}

func TestRegistryEntriesAreWellFormed(t *testing.T) {
	name := regexp.MustCompile(`^[a-z]+(\.[a-z][a-z0-9_]*)+$`)
	seen := map[string]bool{}
	for _, e := range Entries() {
		if !name.MatchString(e.Name) {
			t.Errorf("name %q is not a dotted lowercase key", e.Name)
		}
		if seen[e.Name] {
			t.Errorf("duplicate key %q", e.Name)
		}
		seen[e.Name] = true
		if e.Min > e.Default || e.Default > e.Max {
			t.Errorf("%s: default %d is outside %d..%d", e.Name, e.Default, e.Min, e.Max)
		}
		if !strings.HasSuffix(e.Doc, ".") || strings.Count(e.Doc, ". ") > 0 {
			t.Errorf("%s: the description must be one sentence that ends in a period: %q", e.Name, e.Doc)
		}
		if n := len(strings.Fields(e.Doc)); n > 25 {
			t.Errorf("%s: the description has %d words, want at most 25", e.Name, n)
		}
		if strings.ContainsAny(e.Doc, "\u2014\u2192|") {
			t.Errorf("%s: the description has a character that the style rules forbid", e.Name)
		}
	}
}

func TestDocsMatchRegistry(t *testing.T) {
	path := filepath.Join("..", "..", "..", "docs", "cli.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout can turn the line feeds of the file into CR LF.
	doc := strings.ReplaceAll(string(raw), "\r\n", "\n")
	begin := strings.Index(doc, tableBegin)
	end := strings.Index(doc, tableEnd)
	if begin < 0 || end < begin {
		t.Fatalf("%s lacks the markers %s and %s", path, tableBegin, tableEnd)
	}
	want := doc[:begin+len(tableBegin)] + "\n" + MarkdownTable() + doc[end:]
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if doc != want {
		t.Errorf("the tunables table in %s differs from the registry; run: go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update", path)
	}
}
