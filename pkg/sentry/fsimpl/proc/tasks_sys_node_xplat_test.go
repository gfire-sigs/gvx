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

package proc

import (
	"errors"
	"math"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestParseReservedPortsCanonicalizesRanges(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    string
		wantErr bool
	}{
		{name: "empty clears the list", text: "\n", want: ""},
		{name: "one port", text: "80", want: "80"},
		{name: "ports and ranges are sorted", text: "8000-8010,80,81", want: "80-81,8000-8010"},
		{name: "overlapping ranges merge", text: "10-20,15-30", want: "10-30"},
		{name: "duplicates collapse", text: "5,5,5", want: "5"},
		{name: "white space separates entries", text: "1 3\n", want: "1,3"},
		{name: "top of the port space", text: "65535", want: "65535"},
		{name: "port above 65535", text: "65536", wantErr: true},
		{name: "backward range", text: "20-10", wantErr: true},
		{name: "not a number", text: "web", wantErr: true},
		{name: "negative port", text: "-1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseReservedPorts(tc.text, "")
			if tc.wantErr {
				if !errors.Is(err, linuxerr.EINVAL) {
					t.Fatalf("parseReservedPorts(%q) = %q, %v, want EINVAL", tc.text, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("parseReservedPorts(%q) = %q, %v, want %q", tc.text, got, err, tc.want)
			}
		})
	}
}

func TestIntVecParserAppliesLinuxRanges(t *testing.T) {
	overcommit := intVecParser(1, 0, 2, nil)
	for _, text := range []string{"0", "1\n", " 2 "} {
		if _, err := overcommit(text, "0"); err != nil {
			t.Errorf("overcommit parser rejects %q: %v", text, err)
		}
	}
	for _, text := range []string{"3", "-1", "x", "1 2"} {
		if got, err := overcommit(text, "0"); !errors.Is(err, linuxerr.EINVAL) {
			t.Errorf("overcommit parser on %q = %q, %v, want EINVAL", text, got, err)
		}
	}

	any32 := intVecParser(1, math.MinInt32, math.MaxInt32, nil)
	if got, err := any32("-7", "0"); err != nil || got != "-7" {
		t.Errorf("a 32-bit parser on -7 = %q, %v, want -7", got, err)
	}
	if got, err := any32("2147483648", "0"); !errors.Is(err, linuxerr.EINVAL) {
		t.Errorf("a 32-bit parser on 2^31 = %q, %v, want EINVAL", got, err)
	}
}

func TestIntVecParserKeepsTheRestOfAVector(t *testing.T) {
	pingGroups := intVecParser(2, 0, maxGroupID, fixPingGroupRange)
	tests := []struct {
		name, text, cur, want string
	}{
		{"both values", "100 200", "1\t0", "100\t200"},
		{"first value only", "5", "1\t9", "5\t9"},
		{"reversed range becomes empty", "10 5", "100\t200", "1\t0"},
		{"white space changes nothing", "\n", "100\t200", "100\t200"},
		{"largest group ID", "0 4294967294", "1\t0", "0\t4294967294"},
	}
	for _, tc := range tests {
		got, err := pingGroups(tc.text, tc.cur)
		if err != nil || got != tc.want {
			t.Errorf("%s: parse(%q, %q) = %q, %v, want %q", tc.name, tc.text, tc.cur, got, err, tc.want)
		}
	}
	if got, err := pingGroups("1 2 3", "1\t0"); !errors.Is(err, linuxerr.EINVAL) {
		t.Errorf("three values = %q, %v, want EINVAL", got, err)
	}
	if got, err := pingGroups("0 4294967295", "1\t0"); !errors.Is(err, linuxerr.EINVAL) {
		t.Errorf("group ID 4294967295 = %q, %v, want EINVAL", got, err)
	}
}

func TestStackSecondsAcceptsLinuxZero(t *testing.T) {
	for seconds, want := range map[int]time.Duration{0: time.Second, 1: time.Second, 75: 75 * time.Second} {
		if got := stackSeconds(seconds); got != want {
			t.Errorf("stackSeconds(%d) = %v, want %v", seconds, got, want)
		}
	}
}
